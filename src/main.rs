//! # SNI router.
//!
//! TCP terminating server that snoops on TLS SNI, and then passes the FD on to
//! another server, like [tarweb][tarweb]. Or if the other server doesn't
//! support FD passing, it proxies the connection via the PROXY v1 protocol.
//!
//! The idea here is to actually make different routing decisions based on SNI,
//! and depending on the match, either pass the FD, or do TCP level proxying.
//!
//! Optionally, the SNI router can also do the TLS handshake, and set up kTLS,
//! so that the other server can just treat the connection as plaintext. This is
//! called "frontend TLS".
//!
//! If you enable *both* proxying (i.e. not FD passing) and TLS handshaking,
//! then make sure that the path to the other server is not going over an
//! unencrypted channel, such as plain ethernet. You'll want it to be localhost,
//! or over some VPN, since the connection to the backend will not be encrypted.
//!
//! ## Notable
//!
//! * Under extremely heavy fd passing, `net.unix.max_dgram_qlen` could possibly
//!   become a factor.
//!
//! ## TODO
//!
//! * Think more about how to best degrade if `sendmsg()` passing the FD fails
//!   with `EMSGSIZE`. Queue? Drop?
//! * Maybe leave the unix socket connected, and only try to reconnect on error?
//! * Add a bunch of tests.
//!
//! [tarweb]: https://github.com/ThomasHabets/tarweb
// Disable overly pedantic pedantic-level clippy lints.
#![allow(clippy::similar_names)]

use std::net::ToSocketAddrs;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::LazyLock;

use prometheus::Histogram;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

mod privs;

use anyhow::anyhow;
use anyhow::{Context, Result, bail};
use clap::Parser;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixDatagram;
use tracing::{debug, error, info, trace, warn};

mod protos {
    include!(concat!(env!("OUT_DIR"), "/sni_router.rs"));
}

// How much capacity to prepare for ClientHello and stuff.
const BUF_CAPACITY: usize = 2048;
const UNKNOWN_SNI: &str = "<unknown>";
const MISSING_SNI: &str = "<missing>";

static REGISTRY: LazyLock<prometheus::Registry> = LazyLock::new(prometheus::Registry::new);

static ACCEPTS: LazyLock<prometheus::IntCounter> = LazyLock::new(|| {
    let metric = prometheus::IntCounter::new("tcp_accept", "Total TCP connects").unwrap();
    REGISTRY.register(Box::new(metric.clone())).unwrap();
    metric
});

static SNI: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    let metric = prometheus::IntCounterVec::new(
        prometheus::Opts::new("sni", "Clienthellos with SNI"),
        &["sni"],
    )
    .unwrap();
    REGISTRY.register(Box::new(metric.clone())).unwrap();
    metric
});

static HANDSHAKE_LATENCY: LazyLock<prometheus::Histogram> = LazyLock::new(|| {
    use prometheus::HistogramOpts;
    let metric = Histogram::with_opts(
        HistogramOpts::new("handshake_latency_ms", "Handshake latency")
            .buckets(prometheus::exponential_buckets(1.0, 2.0f64.sqrt(), 40).unwrap()),
    )
    .unwrap();
    REGISTRY.register(Box::new(metric.clone())).unwrap();
    metric
});

static HOSTNAME: LazyLock<String> = LazyLock::new(|| {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .map(|s| s.trim_end().to_owned())
                .unwrap_or_else(|_| "unknown".to_owned())
        })
});

fn push_metrics() -> Result<()> {
    info!("Pushing metrics");
    let grouping = std::collections::HashMap::from([("instance".to_string(), (*HOSTNAME).clone())]);

    prometheus::push_metrics(
        "sni-router",            // job name
        grouping,                // grouping labels
        "http://localhost:9091", // Pushgateway URL
        REGISTRY.gather(),
        None, // optional basic auth
    )?;
    Ok(())
}

/// Load certificate chain from file.
///
/// # Errors
///
/// Probably file not readable or parsable.
fn load_certs<P: AsRef<std::path::Path>>(filename: P) -> Result<Vec<CertificateDer<'static>>> {
    let filename = filename.as_ref();
    let pem = CertificateDer::pem_file_iter(filename)
        .context(format!("Loading certs from {}", filename.display()))?;
    let r: Result<_, rustls::pki_types::pem::Error> = pem.collect();
    Ok(r?)
}

/// Load private key from file.
///
/// # Errors
///
/// Probably file not readable or parsable.
fn load_private_key<P: AsRef<std::path::Path>>(filename: P) -> Result<PrivateKeyDer<'static>> {
    let filename = filename.as_ref();
    PrivateKeyDer::from_pem_file(filename)
        .context(format!("Loading private key from {}", filename.display()))
}

/// Set TCP NODELAY via a standard sync call.
///
/// # Errors
///
/// System setsockopt errors.
fn set_nodelay(fd: libc::c_int) -> anyhow::Result<()> {
    let flag: libc::c_int = 1; // Enable TCP_NODELAY (disable Nagle)
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP, // Protocol
            libc::TCP_NODELAY, // Option
            (&raw const flag).cast::<libc::c_void>(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())?,
        )
    };

    if ret == -1 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(())
}

/// SNI router.
///
/// <https://github.com/ThomasHabets/sni-router>
#[derive(clap::Parser)]
#[clap(version)]
struct Opt {
    /// Verbosity level. Can be error, warn info, debug, or trace.
    #[arg(long, short, default_value = "info")]
    verbose: String,

    /// Address to listen to.
    #[arg(long, short, default_value = "[::]:443")]
    listen: std::net::SocketAddr,

    /// Restrict router to only be able to read under this directory.
    #[arg(long, default_value = "/")]
    restrict_dirs: Vec<std::path::PathBuf>,

    /// Allow keylogging.
    #[arg(long)]
    allow_keylogging: bool,

    /// Asciiproto config.
    #[arg(long, short)]
    config: String,
}

/// Load TLS data from files as specified in the proto part.
#[allow(clippy::unnecessary_wraps)]
fn load_tls(
    cfg: Option<&protos::backend::Tls>,
    allow_keylogging: bool,
) -> Result<Option<Arc<rustls::ServerConfig>>> {
    let Some(cfg) = cfg else {
        return Ok(None);
    };
    let certs = load_certs(&cfg.cert_file)?;
    let key = load_private_key(&cfg.key_file)?;
    Ok(Some(Arc::new({
        let mut cfg = rustls::ServerConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS12,
            &rustls::version::TLS13,
        ])
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
        cfg.enable_secret_extraction = true;
        // Enable key log file to file named from env SSLKEYLOGFILE.
        if allow_keylogging {
            cfg.key_log = Arc::new(rustls::KeyLogFile::new());
        }
        cfg
    })))
}

/// Load ACL from the parsed proto.
fn load_acl(pb: &protos::Acl) -> Result<Acl> {
    let mut rules = Vec::new();
    for rule in &pb.rules {
        let source: ipnet::IpNet = rule
            .source
            .parse()
            .context(format!("parsing cidr {}", rule.source))?;
        let source = match source {
            ipnet::IpNet::V4(v4net) => {
                let net = v4net.network().to_ipv6_mapped();
                let prefix = 96 + v4net.prefix_len();
                ipnet::Ipv6Net::new(net, prefix)?
            }
            ipnet::IpNet::V6(v6) => v6,
        };
        if rule.action() == protos::AclAction::Unspecified {
            return Err(anyhow!("ACL action can't be 'UNSPECIFIED'"));
        }
        rules.push(AclRule {
            source,
            action: rule.action().clone(),
        });
    }
    Ok(Acl {
        rules,
        default_action: pb.default_action(),
    })
}

/// Load backend config from the parsed proto.
///
/// This includes loading the TLS cert/key, so it's not just proto data
/// transformation.
fn load_backend(
    be: &protos::backend::BackendType,
    frontend_tls: Option<&protos::backend::Tls>,
    sorry: Option<&protos::Backend>,
    allow_keylogging: bool,
) -> Result<Backend> {
    if sorry.is_some_and(|s| s.sorry.is_some()) {
        return Err(anyhow!("sorry servers can't have sorry servers"));
    }
    let sorry = sorry
        .map(|s| {
            load_backend(
                s.backend_type.as_ref().unwrap(),
                s.frontend_tls.as_ref(),
                None,
                allow_keylogging,
            )
        })
        .transpose()?
        .map(Box::new);
    Ok(match be {
        protos::backend::BackendType::Null(_) => {
            if sorry.is_some() {
                return Err(anyhow!("null backend with sorry server not allowed"));
            }
            Backend::Null
        }
        protos::backend::BackendType::Proxy(p) => Backend::Proxy {
            addr: p.addr.clone(),
            proxy_header: p.proxy_header,
            frontend_tls: load_tls(frontend_tls, allow_keylogging)?,
            sorry,
        },
        protos::backend::BackendType::Pass(p) => Backend::Pass {
            path: p.path.clone().into(),
            frontend_tls: load_tls(frontend_tls, allow_keylogging)?,
            sorry,
        },
    })
}

/// Attempt to load the config from file. This transitively loads any TLS
/// cert/key too.
fn load_config(filename: &str, allow_keylogging: bool) -> Result<Config> {
    let pool = prost_reflect::DescriptorPool::decode(PROTO_DESCRIPTOR)?;
    let md = pool
        .get_message_by_name("sni_router.SNIConfig")
        .ok_or(anyhow!("Unable to reflect SNIConfig"))?;
    let cwd = std::env::current_dir()
        .map(|c| c.display().to_string())
        .unwrap_or("<unknown>".to_string());
    let txt = std::fs::read_to_string(filename)
        .context(anyhow!("opening {filename:?} from cwd {cwd:?}"))?;
    let dyn_msg = prost_reflect::DynamicMessage::parse_text_format(md, &txt)?;

    let protocfg: protos::SniConfig = dyn_msg.transcode_to()?;

    let mut config = Config {
        max_lifetime: if protocfg.max_lifetime_ms > 0 {
            Some(tokio::time::Duration::from_millis(protocfg.max_lifetime_ms))
        } else {
            None
        },
        handshake_timeout: if protocfg.handshake_timeout_ms > 0 {
            Some(tokio::time::Duration::from_millis(
                protocfg.handshake_timeout_ms,
            ))
        } else {
            None
        },
        rules: vec![],
        default: {
            let rule = load_rule(
                &protocfg.default.ok_or(anyhow!("default rule is missing"))?,
                true,
                allow_keylogging,
            )?;
            if rule.re.as_str() != "" {
                return Err(anyhow!("default rule can't have regex"));
            }
            rule
        },
    };
    for rule in protocfg.rules {
        config
            .rules
            .push(load_rule(&rule, false, allow_keylogging)?);
    }
    Ok(config)
}

fn load_rule(rule: &protos::Rule, is_default: bool, allow_keylogging: bool) -> Result<Rule> {
    let re = if is_default {
        if let Some(r) = rule.regex.as_ref() {
            return Err(anyhow!("default rule can't have regex. Had {r}"));
        }
        ""
    } else {
        rule.regex
            .as_ref()
            .ok_or(anyhow!("No regex supplied in rule"))?
    };
    Ok(Rule {
        re: regex::Regex::new(re)?,
        acl: rule.acl.as_ref().map_or(
            Ok(Acl {
                rules: vec![],
                default_action: protos::AclAction::Accept,
            }),
            |a| load_acl(&a),
        )?,
        timeout: {
            let t = rule.max_lifetime_ms;
            if t > 0 {
                Some(tokio::time::Duration::from_millis(t))
            } else {
                None
            }
        },
        backend: {
            let (be, frontend_tls, sorry) = rule
                .backend
                .as_ref()
                .map(|d| (&d.backend_type, d.frontend_tls.as_ref(), d.sorry.as_deref()))
                .ok_or(anyhow!("rule missing backend"))?;
            load_backend(
                be.as_ref()
                    .ok_or(anyhow!("backend missing actual backend"))?,
                frontend_tls,
                sorry,
                allow_keylogging,
            )?
        },
    })
}
/// Read enough bytes from `stream` to cover the entire TLS `ClientHello` handshake
/// (which may span multiple records). Returns the handshake (type+len+body).
///
/// TLS record format:
///   - 5B header: `content_type(1)=22`, `legacy_version(2)`, length(2)
///   - payload: one or more handshake messages
///
/// Handshake header:
///   - `msg_type(1)=1(ClientHello)`
///   - length(3) = `body_len`
///
/// Return all bytes read, and clienthello bytes.
///
/// This function is mostly AI coded for the parsing parts. Seems to work, and
/// reviewing it it seems safe.
async fn read_tls_clienthello(
    stream: &mut tokio::net::TcpStream,
) -> Result<(Vec<u8>, Result<Vec<u8>>)> {
    const REC_HDR_LEN: usize = 5;
    let mut hello = Vec::with_capacity(BUF_CAPACITY);
    let mut bytes = Vec::with_capacity(BUF_CAPACITY);

    // We need at least first record to see handshake header (type + 3-byte len).
    // Loop records until we have full ClientHello bytes (4 + body_len).
    let mut needed: Option<usize> = None;

    while needed.is_none_or(|n| hello.len() < n) {
        // Read record header.
        let mut rec_hdr = [0u8; REC_HDR_LEN];
        stream
            .read_exact(&mut rec_hdr)
            .await
            .context("read TLS record header")?;
        bytes.extend(rec_hdr);

        // Parse header.
        let content_type = rec_hdr[0];
        let _legacy_ver = u16::from_be_bytes([rec_hdr[1], rec_hdr[2]]);
        let rec_len = u16::from_be_bytes([rec_hdr[3], rec_hdr[4]]) as usize;

        // Confirm it's Handshake.
        if content_type != 22 {
            return Ok((
                bytes,
                Err(anyhow!(
                    "unexpected TLS content_type {content_type}, want 22 (handshake)"
                )),
            ));
        }
        if rec_len == 0 {
            return Ok((bytes, Err(anyhow!("zero-length TLS record"))));
        }

        // Read whole record.
        let mut rec_payload = vec![0u8; rec_len];
        stream
            .read_exact(&mut rec_payload)
            .await
            .context("read TLS record payload")?;

        // Append to handshake buffer (could contain partial or full ClientHello).
        hello.extend(&rec_payload);
        bytes.extend(&rec_payload);

        // If we haven't established how many bytes we need, try now.
        if needed.is_none() {
            if hello.len() < 4 {
                // Not enough to read handshake header yet; continue.
                continue;
            }
            let msg_type = hello[0];
            if msg_type != 1 {
                return Ok((
                    bytes,
                    Err(anyhow!(
                        "first handshake msg is type {msg_type}, expected 1 (ClientHello)"
                    )),
                ));
            }
            let body_len =
                ((hello[1] as usize) << 16) | ((hello[2] as usize) << 8) | (hello[3] as usize);
            needed = Some(4 + body_len);
        }
    }

    // Truncate to exactly the ClientHello (in case next record started).
    // TODO: that's impossible, right?
    let n = needed.unwrap();
    if hello.len() > n {
        hello.truncate(n);
    }
    Ok((bytes, Ok(hello)))
}

/// Send file descriptor and handshake data using `SCM_RIGHTS` on a Unix datagram.
async fn pass_fd_over_uds(
    stream: tokio::net::TcpStream,
    sock: UnixDatagram,
    bytes: Vec<u8>,
) -> Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};

    let fd = stream.as_raw_fd();
    let iov = [std::io::IoSlice::new(&bytes)];
    let cmsg = [ControlMessage::ScmRights(&[fd])];

    // Async wait until it *should* be fine to write.
    sock.writable().await.context("checking UDS for writable")?;

    // Send sync, but per above *should* be fine to write. Also with
    // `MSG_DONTWAIT` it shouldn't block.
    //
    // This error is sorryable, if it failed in its entirety.
    let sent = sendmsg::<()>(
        sock.as_raw_fd(),
        &iov,
        &cmsg,
        MsgFlags::MSG_NOSIGNAL | MsgFlags::MSG_DONTWAIT,
        None,
    )
    .context("sendmsg SCM_RIGHTS")?;

    if sent != bytes.len() {
        // This is not sorryable.
        return Err(anyhow!(
            "sendmsg: expected to send {} bytes, sent {sent}",
            bytes.len()
        ));
    }
    Ok(())
}

/// Extract SNI `host_name` from a TLS `ClientHello` (handshake header + body).
/// Returns Ok(Some(host)) if found, Ok(None) if no SNI extension exists.
///
/// This function is mostly jipptycoded. Seems to work, and reviewing it it seems
/// safe.
fn extract_sni(clienthello: &[u8]) -> Result<Option<String>> {
    // Handshake header: type(1)=1, len(3)
    if clienthello.len() < 4 {
        bail!("ClientHello too short for handshake header");
    }
    if clienthello[0] != 1 {
        bail!("not a ClientHello (handshake type {})", clienthello[0]);
    }
    let body_len = ((clienthello[1] as usize) << 16)
        | ((clienthello[2] as usize) << 8)
        | (clienthello[3] as usize);
    if clienthello.len() < 4 + body_len {
        bail!("truncated ClientHello body");
    }
    let body = &clienthello[4..4 + body_len];

    let mut i = 0usize;
    // legacy_version(2) + random(32) + session_id_len(1)
    if body.len() < 35 {
        bail!("ClientHello body too short");
    }
    i += 2 + 32;
    let sid_len = body[i] as usize;
    i += 1;
    if body.len() < i + sid_len {
        bail!("truncated session_id");
    }
    i += sid_len;

    // cipher_suites: len(2) + entries (each 2 bytes)
    if body.len() < i + 2 {
        bail!("missing cipher_suites length");
    }
    let cs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + cs_len || !cs_len.is_multiple_of(2) {
        bail!("invalid cipher_suites vector");
    }
    i += cs_len;

    // compression_methods: len(1) + values
    if body.len() < i + 1 {
        bail!("missing compression_methods length");
    }
    let cmethod_len = body[i] as usize;
    i += 1;
    if body.len() < i + cmethod_len {
        bail!("invalid compression_methods vector");
    }
    i += cmethod_len;

    // optional extensions: len(2) + vector
    if i == body.len() {
        return Ok(None); // no extensions -> no SNI
    }
    if body.len() < i + 2 {
        bail!("missing extensions length");
    }
    let ext_total = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + ext_total {
        bail!("truncated extensions block");
    }

    let mut j = i;
    while j + 4 <= i + ext_total {
        let etype = u16::from_be_bytes([body[j], body[j + 1]]);
        let elen = u16::from_be_bytes([body[j + 2], body[j + 3]]) as usize;
        j += 4;
        if j + elen > i + ext_total {
            bail!("truncated extension body");
        }
        if etype == 0x0000 {
            // server_name ext
            let ext = &body[j..j + elen];
            if ext.len() < 2 {
                bail!("server_name: missing list length");
            }
            let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
            if ext.len() < 2 + list_len {
                bail!("server_name: truncated list");
            }
            let mut k = 2usize;
            while k + 3 <= 2 + list_len {
                let name_type = ext[k];
                let host_len = u16::from_be_bytes([ext[k + 1], ext[k + 2]]) as usize;
                k += 3;
                if k + host_len > 2 + list_len {
                    bail!("server_name: truncated host entry");
                }
                if name_type == 0 {
                    let host_bytes = &ext[k..k + host_len];
                    // RFC 6066: ASCII, no trailing dot, no NULs. We’ll do a lossy UTF-8 just in case.
                    let host = String::from_utf8_lossy(host_bytes).to_string();
                    return Ok(Some(host));
                }
                k += host_len;
            }
            // SNI ext present but no host_name item
            return Ok(None);
        }
        j += elen;
    }

    Ok(None)
}

/// In process backend config.
///
/// This is not just the proto because TLS configs are loaded too, and it
/// includes other TLS server configs set.
#[derive(Debug)]
enum Backend {
    // Just close the connection.
    Null,

    // Connect to a unix socket and pass in bytes read so far, and the file
    // descriptor to continue.
    Pass {
        path: std::path::PathBuf,
        frontend_tls: Option<Arc<rustls::ServerConfig>>,
        sorry: Option<Box<Backend>>,
    },

    // Proxy string. DNS resolved on every new connection.
    //
    // If a TlsConfig is provided then the handshake and kTLS setup is done by
    // the SNI router.
    Proxy {
        addr: String,
        proxy_header: bool,
        frontend_tls: Option<Arc<rustls::ServerConfig>>,
        sorry: Option<Box<Backend>>,
    },
}

#[derive(Debug, Clone)]
struct Acl {
    rules: Vec<AclRule>,
    default_action: protos::AclAction,
}

#[derive(Debug, Clone)]
struct AclRule {
    source: ipnet::Ipv6Net,
    action: protos::AclAction,
}

#[derive(Debug)]
struct Rule {
    re: regex::Regex,
    backend: Backend,
    acl: Acl,
    timeout: Option<tokio::time::Duration>,
}

#[derive(Debug)]
struct Config {
    max_lifetime: Option<tokio::time::Duration>,
    handshake_timeout: Option<tokio::time::Duration>,
    rules: Vec<Rule>,
    default: Rule,
}

/// After going through rules, sorries and backups, we have finally found and
/// connected to the backend we're going to use.
///
/// The timeout is either the global config max lifetime or a per rule maximum.
///
/// The thing that actually connects to a backend doesn't know what the timeout
/// is, nor does the connection loop need to know, so `ConnectedBackend` doesn't
/// contain the timeout.
struct RoutedConnection {
    sni: Option<String>,
    backend: ConnectedBackend,
    timeout: Option<tokio::time::Duration>,
}

/// A successfull connect has happened, and just needs to do its thing.
enum ConnectedBackend {
    /// File descriptor passed to another process. Nothing more to do.
    Done,

    /// All the data needed to handshake with the backend and proxy the
    /// connection.
    ///
    /// Timeout is already applied to the reader of this at call time.
    Proxy {
        stream: tokio::net::TcpStream,
        bytes: Vec<u8>,
        conn: tokio::net::TcpStream,
        proxy_header: bool,
        frontend_tls: Option<Arc<rustls::ServerConfig>>,
    },
}

/// Perform TLS handshake and setsockopt with kTLS.
///
/// Returns the new stream and the new initial bytes.
async fn tls_handshake(
    mut stream: tokio::net::TcpStream,
    mut bytes: Vec<u8>,
    cfg: Arc<rustls::ServerConfig>,
) -> Result<(tokio::net::TcpStream, Vec<u8>)> {
    use std::io::Read;
    use tokio::io::AsyncWriteExt;

    debug!("Handshaking…");
    let handshake_start = std::time::Instant::now();

    // If this fails, we could actually still continue with a sorry server in
    // the caller, but it seems like a very unlikely case, so let's just fail.
    //
    // Anything after creating the config is unsafe to go to sorry-server.
    let mut tls = rustls::ServerConnection::new(cfg)
        .context("creating TLS server config: This is sorry-able, but is not implemented")?;
    loop {
        // Give bytes we have to rustls.
        {
            let mut cur = std::io::Cursor::new(&bytes);
            let n = tls.read_tls(&mut cur).context("reading TLS")?;
            bytes.drain(0..n);
        }
        let io = tls
            .process_new_packets()
            .context("processing TLS packets")?;

        // Send rustls bytes to the peer.
        let bytes_to_write = io.tls_bytes_to_write();
        if bytes_to_write > 0 {
            let mut buf = vec![0u8; bytes_to_write];
            let mut cur = std::io::Cursor::new(&mut buf);
            let n = tls.write_tls(&mut cur).context("writing TLS")?;
            // TODO: can we assume remote side will not be overwhelmed?
            // If it is, and insists on writing, then we deadlock (time out).
            stream
                .write_all(&buf[..n])
                .await
                .context("writing as part of handshake")?;
        }
        let still_handshaking = tls.is_handshaking();
        if !still_handshaking {
            HANDSHAKE_LATENCY.observe(handshake_start.elapsed().as_millis() as f64);
            let plain_n = io.plaintext_bytes_to_read();
            let mut buf = vec![0u8; plain_n];
            let n = tls
                .reader()
                .read(&mut buf[..plain_n])
                .context("reading when handshake done")?;
            assert_eq!(plain_n, n);

            // Enable initial TLS option.
            let ulp_name = b"tls\0";
            let rc = unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_TCP,
                    libc::TCP_ULP,
                    ulp_name.as_ptr().cast(),
                    ulp_name.len().try_into()?,
                )
            };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow!("setsockopt(SOL_TCP/TCP_ULP)=>{rc}: {err}"));
            }

            // Hand over keys.
            let suite = tls
                .negotiated_cipher_suite()
                .ok_or(anyhow!("failed to get negotiated cipher suite"))?;
            let keys = tls.dangerous_extract_secrets().context("extracting keys")?;
            let tls_rx =
                ktls::CryptoInfo::from_rustls(suite, keys.rx).context("extracting rx keys")?;
            let tls_tx =
                ktls::CryptoInfo::from_rustls(suite, keys.tx).context("extracting tx keys")?;
            for (name, s) in [(libc::TLS_RX, tls_rx), (libc::TLS_TX, tls_tx)] {
                let rc = unsafe {
                    libc::setsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_TLS,
                        name,
                        s.as_ptr(),
                        s.size().try_into()?,
                    )
                };
                if rc < 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(anyhow!("setsockopt(SOL_TLS)=>{rc}: {err}"));
                }
            }
            return Ok((stream, buf));
        }

        // Handshake still going.
        let mut buf = [0u8; 4096];
        let n = stream
            .read(&mut buf)
            .await
            .context("reading during handshake")?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF during handshake",
            )
            .into());
        }
        bytes.extend(&buf[..n]);

        // TODO: what should this magic value be?
        if bytes.len() > 8192 {
            return Err(anyhow!("max TLS outstanding size exceeded"));
        }
    }
}

/// Do a connect for proxied connections.
///
/// This is called under handshake timeout, and failure will fall back to sorry
/// server.
async fn connect_for_proxy(id: usize, addr: &str) -> Result<tokio::net::TcpStream> {
    let addrs = addr
        .to_socket_addrs()
        .context(format!("parsing backend address {addr}"))?;
    let mut conn = None;
    for addr in addrs {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(ok) => {
                trace!("id={id} Connected to backend {addr}");
                conn = Some(ok);
                break;
            }
            Err(e) => {
                debug!("id={id} Failed to connect to backend {addr:?}: {e}");
            }
        }
    }
    conn.ok_or(anyhow!(
        "failed to connect to any backend with address {addr}"
    ))
}

/// After fully connected, and handshake timeout no longer relevant, run the
/// remaining proxying.
///
/// Any failure here will NOT fall back to sorry servers, as we're already
/// connected.
async fn handle_connected_backend(id: usize, backend: ConnectedBackend) -> Result<()> {
    match backend {
        // No proxying needed if fd was passed.
        ConnectedBackend::Done => Ok(()),

        ConnectedBackend::Proxy {
            stream,
            bytes,
            conn,
            proxy_header,
            frontend_tls,
        } => handle_connected_proxy(id, stream, bytes, conn, proxy_header, frontend_tls).await,
    }
}

/// Do any frontend TLS and work with the already connected backend proxy.
///
/// Any failure here will NOT fall back to sorry servers, as we're already
/// connected.
async fn handle_connected_proxy(
    id: usize,
    stream: tokio::net::TcpStream,
    bytes: Vec<u8>,
    mut conn: tokio::net::TcpStream,
    proxy_header: bool,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let (mut stream, bytes) = if let Some(tls) = tls {
        // TODO: increment handshake fail counter.
        tls_handshake(stream, bytes, tls).await?
    } else {
        (stream, bytes)
    };
    let (mut up_r, mut up_w) = conn.split();
    let (mut down_r, mut down_w) = stream.split();
    let upstream = async {
        if proxy_header {
            let me = down_r.local_addr().context("getting local address")?;
            let peer = down_r.peer_addr().context("getting peer address")?;
            let src_port = peer.port();
            let src_addr = peer.ip().to_string();
            let proto = if peer.is_ipv4() {
                "TCP4"
            } else if peer.is_ipv6() {
                "TCP6"
            } else {
                "UNKNOWN"
            };
            let dst_addr = me.ip().to_string();
            let dst_port = me.port();
            up_w.write_all(
                format!("PROXY {proto} {src_addr} {dst_addr} {src_port} {dst_port}\r\n").as_bytes(),
            )
            .await
            .context("writing proxy line")?;
        }
        // Re-write ClientHello or anything else pre-read.
        up_w.write_all(&bytes)
            .await
            .context("writing preamble to proxied backend")?;
        tokio::io::copy(&mut down_r, &mut up_w)
            .await
            .context("upstream copying")?;
        up_w.shutdown()
            .await
            .context("failed to shut down upstream writer")?;
        trace!("id={id} Upstream write completed");
        Ok::<_, anyhow::Error>(())
    };
    let downstream = async {
        tokio::io::copy(&mut up_r, &mut down_w)
            .await
            .context("downstream copying")?;
        down_w
            .shutdown()
            .await
            .context("failed to shut down downstream writer")?;
        trace!("id={id} Downstream write completed");
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(upstream, downstream)?;
    Ok(())
}

/// Having found a matching backend config (incl sorry server fallback), we try
/// to connect to it.
///
/// TODO: Document why this creates a box pinned future instead of just being
/// async. IIRC it had something to do with circular references or something.
fn connect_or_handoff_backend<'a>(
    id: usize,
    stream: tokio::net::TcpStream,
    bytes: Vec<u8>,
    backend: &'a Backend,
) -> Pin<Box<dyn std::future::Future<Output = Result<ConnectedBackend>> + Send + 'a>> {
    Box::pin(async move {
        match backend {
            Backend::Null => {
                trace!("id={id} Null backend. Closing");
                Ok(ConnectedBackend::Done)
            }
            Backend::Pass {
                path,
                frontend_tls,
                sorry,
            } => {
                // Connecting to a UnixDatagram should be cheap, and not at all be
                // visible to the backend. It's only when we SendMsg that it can
                // cause any load. So we first do this connect, so that we don't
                // needlessly do a handshake only to then never connect to anything.
                //
                // Besides, perhaps the sorry server doesn't have frontend TLS
                // enabled.
                let sock = tokio::net::UnixDatagram::unbound().context("create UnixDatagram")?;
                if let Err(e) = sock
                    .connect(path)
                    .with_context(|| format!("connect to {:?}", path.display()))
                {
                    info!("Primary backend connect failure: {e}");
                    if let Some(s) = sorry {
                        return connect_or_handoff_backend(id, stream, bytes, s).await;
                    }
                    return Err(e);
                }
                // This doesn't work, because we're using DGRAM. Maybe it works with
                // SEQPACKET?
                if false {
                    // While this error is sorry-able, but since it doesn't work
                    // anyway, shrug.
                    let ucred = nix::sys::socket::getsockopt(
                        &sock,
                        nix::sys::socket::sockopt::PeerCredentials,
                    )?;
                    debug!(
                        "id={id} peer pid={} uid={} gid={}",
                        ucred.pid(),
                        ucred.uid(),
                        ucred.gid()
                    );
                }
                let (stream, bytes) = if let Some(tls) = frontend_tls {
                    // TODO: increment handshake fail counter.
                    tls_handshake(stream, bytes, tls.clone()).await?
                } else {
                    (stream, bytes)
                };
                pass_fd_over_uds(stream, sock, bytes).await?;
                Ok(ConnectedBackend::Done)
            }
            Backend::Proxy {
                addr,
                proxy_header,
                frontend_tls,
                sorry,
            } => {
                let conn = match connect_for_proxy(id, addr).await {
                    Ok(c) => c,
                    Err(e) => {
                        info!("Primary backend connect failure: {e}");
                        return match sorry {
                            None => Err(e),
                            Some(s) => connect_or_handoff_backend(id, stream, bytes, s).await,
                        };
                    }
                };
                Ok(ConnectedBackend::Proxy {
                    stream,
                    bytes,
                    conn,
                    proxy_header: *proxy_header,
                    frontend_tls: frontend_tls.clone(),
                })
            }
        }
    })
}

/// Same as `connect_or_handoff_backend`, but with the per rule timeout when
/// trying to connect to that backend.
///
/// It's also running under the global `max_lifetime_ms`, like everything else.
async fn connect_or_handoff_backend_with_timeout(
    id: usize,
    stream: tokio::net::TcpStream,
    bytes: Vec<u8>,
    backend: &Backend,
    timeout: Option<tokio::time::Duration>,
) -> Result<ConnectedBackend> {
    let fut = connect_or_handoff_backend(id, stream, bytes, backend);
    if let Some(timeout) = timeout {
        match tokio::time::timeout(timeout, fut).await {
            Ok(r) => r,
            Err(e) => Err(anyhow!("backend connect/handoff timeout: {e}")),
        }
    } else {
        fut.await
    }
}

/// Regex fullmatch wrapper.
fn is_full_match(re: &regex::Regex, text: &str) -> bool {
    match re.find(text) {
        Some(m) => m.start() == 0 && m.end() == text.len(),
        None => false,
    }
}

fn acl_action(acl: &Acl, peer: &std::net::Ipv6Addr) -> protos::AclAction {
    for rule in &acl.rules {
        if rule.source.contains(peer) {
            return rule.action;
        }
    }
    acl.default_action
}

/// Find correct rule and connect to backend.
///
/// This is called under global `max_lifetime_ms` and `handshake_timeout_ms`
/// timeout.
async fn route_and_connect(
    id: usize,
    mut stream: tokio::net::TcpStream,
    config: &Config,
) -> Result<RoutedConnection> {
    let peer = match stream.peer_addr()?.ip() {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        std::net::IpAddr::V6(v6) => v6,
    };
    // Read and validate a full TLS ClientHello.
    let (bytes, clienthello) = read_tls_clienthello(&mut stream).await?;
    match clienthello {
        Ok(clienthello) => {
            debug!("id={id} ClientHello len={} bytes", clienthello.len());
            match extract_sni(&clienthello)? {
                Some(sni) => {
                    debug!("id={id} SNI: {sni:?}");
                    for rule in &config.rules {
                        if !is_full_match(&rule.re, &sni) {
                            continue;
                        }
                        trace!("id={id} SNI {sni} matched rule {rule:?}");
                        match acl_action(&rule.acl, &peer) {
                            protos::AclAction::Unspecified => {
                                error!("Loaded config with ACL with unspecified action");
                                return Err(anyhow!("unspecified ACL action"));
                            }
                            protos::AclAction::Continue => continue,
                            protos::AclAction::Drop => {
                                return Err(anyhow!("{peer:?} rejected by ACL to {}", rule.re));
                            }
                            protos::AclAction::Accept => {}
                        }
                        SNI.with_label_values(&[&sni]).inc();
                        return Ok(RoutedConnection {
                            sni: Some(sni),
                            backend: connect_or_handoff_backend_with_timeout(
                                id,
                                stream,
                                bytes,
                                &rule.backend,
                                rule.timeout,
                            )
                            .await?,
                            timeout: rule.timeout,
                        });
                    }
                    SNI.with_label_values(&[UNKNOWN_SNI]).inc();
                }
                None => {
                    SNI.with_label_values(&[MISSING_SNI]).inc();
                    warn!("id={id} Failed to extract SNI");
                }
            }
        }
        Err(e) => {
            warn!("id={id} Using default backend because no clienthello: {e}");
        }
    }
    Ok(RoutedConnection {
        sni: None,
        backend: connect_or_handoff_backend_with_timeout(
            id,
            stream,
            bytes,
            &config.default.backend,
            config.default.timeout,
        )
        .await?,
        timeout: config.default.timeout,
    })
}

/// Handle connection.
///
/// Called under `max_lifetime_ms` timeout.
async fn handle_conn(id: usize, stream: tokio::net::TcpStream, config: &Config) -> Result<()> {
    let fut = route_and_connect(id, stream, config);
    let routed = if let Some(timeout) = config.handshake_timeout {
        match tokio::time::timeout(timeout, fut).await {
            Ok(r) => r?,
            Err(e) => return Err(anyhow!("handshake timeout: {e}")),
        }
    } else {
        fut.await?
    };

    let fut = handle_connected_backend(id, routed.backend);
    if let Some(timeout) = routed.timeout {
        let to = tokio::time::sleep(timeout);
        tokio::select! {
            res = fut => { res },
            _ = to => {
                Err(anyhow!("Connection to SNI {} timed out", routed.sni.unwrap_or("<no SNI>".to_string())))
            }
        }
    } else {
        fut.await
    }
}

async fn mainloop(
    mut config: Arc<Config>,
    config_filename: &str,
    listener: tokio::net::TcpListener,
    allow_keylogging: bool,
) -> Result<()> {
    let mut id = 0;
    let mut hups = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("Registering SIGHUP");
    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(r) => r,
                Err(e) => {
                    error!("accept() failed: {e}");
                    continue;
                }
            },
            _ = hups.recv() => {
                let cwd = std::env::current_dir().map(|c|c.display().to_string()).unwrap_or("<unknown>".to_string());
                info!("Got SIGHUP. Loading new config {config_filename:?} in cwd {cwd:?}");
                match load_config(config_filename, allow_keylogging) {
                    Ok(c) => config = Arc::new(c),
                    Err(e) => error!(
                        "Failed to load config {config_filename:?}, staying with old config: {e}"
                    ),
                }
                continue;
            }
        };
        ACCEPTS.inc();
        debug!("id={id} fd={} Accepted {}", stream.as_raw_fd(), peer);
        let config = config.clone();
        tokio::spawn(async move {
            let fut = handle_conn(id, stream, &config);
            let res = if let Some(timeout) = config.max_lifetime {
                match tokio::time::timeout(timeout, fut).await {
                    Ok(o) => o,
                    Err(e) => Err(anyhow!("global connection timeout: {e}")),
                }
            } else {
                fut.await
            };
            if let Err(e) = res {
                warn!("id={id} Handling connection to {peer}: {e:#}");
            }
            debug!("id={id} Done");
        });
        id += 1;
    }
}

const PROTO_DESCRIPTOR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/descriptor.bin"));

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    // This is only needed for integration tests, that get multiple crypto
    // implementation features turned on, so we have to pick one.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    tracing_subscriber::fmt()
        //.with_env_filter(format!("sni_router={}", opt.verbose))
        .with_env_filter(&opt.verbose)
        .with_writer(std::io::stderr)
        .init();
    info!(
        "SNI Router {} built with {}",
        env!("GIT_VERSION"),
        env!("RUSTC_VERSION")
    );
    let listener = tokio::net::TcpListener::bind(&opt.listen)
        .await
        .context(format!("listening to {}", opt.listen))?;
    debug!("Listening on {}", listener.local_addr()?);
    privs::sni_drop(
        &opt.restrict_dirs
            .iter()
            .map(std::path::PathBuf::as_path)
            .collect::<Vec<_>>(),
        opt.allow_keylogging,
    )?;
    set_nodelay(listener.as_raw_fd())?;
    // Config.
    let config = load_config(&opt.config, opt.allow_keylogging)
        .context(format!("Loading config {:?}", opt.config))?;
    std::thread::Builder::new()
        .name("prometheus-pusher".to_string())
        .spawn(move || {
            loop {
                if let Err(err) = push_metrics() {
                    eprintln!("failed to push prometheus metrics: {err}");
                }

                std::thread::sleep(std::time::Duration::from_mins(1));
            }
        })
        .expect("spawn prometheus pusher thread");
    mainloop(
        Arc::new(config),
        &opt.config,
        listener,
        opt.allow_keylogging,
    )
    .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::too_many_lines)]
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering;

    const MAX_TEST_CONNECTION_TIME: tokio::time::Duration = tokio::time::Duration::from_secs(5);

    #[test]
    fn config_loads_handshake_timeout() -> Result<()> {
        let tmp_dir = tempfile::TempDir::new()?;
        let config_file = tmp_dir.path().join("config.cfg");
        std::fs::write(
            &config_file,
            r#"
default: <
        backend: <
            null: <>
        >
>
handshake_timeout_ms: 1234
"#,
        )?;

        let config = load_config(config_file.to_str().unwrap(), false)?;
        assert_eq!(
            config.handshake_timeout,
            Some(tokio::time::Duration::from_millis(1234))
        );
        Ok(())
    }

    #[tokio::test]
    async fn default_client() -> Result<()> {
        if false {
            tracing_subscriber::fmt()
                .with_env_filter("trace")
                .with_writer(std::io::stderr)
                .init();
        }
        for curl_opt in ["--tlsv1", "--tlsv1.1", "--tls1.2", "--tls1.3"] {
            for sni in ["foo", "bar", "bar2", "socket"] {
                info!("TESTING: sni={sni} opt={curl_opt}");

                let tmp_dir = tempfile::TempDir::new()?;
                let hit_something = std::sync::atomic::AtomicBool::new(false);
                let listener =
                    tokio::net::TcpListener::bind("[::1]:0".parse::<SocketAddr>()?).await?;
                let listener_port = listener.local_addr()?.port();

                // Backends.
                let backend_bar =
                    tokio::net::TcpListener::bind("[::1]:0".parse::<SocketAddr>()?).await?;
                let backend_bar_port = backend_bar.local_addr()?.port();
                let backend_baz =
                    tokio::net::TcpListener::bind("[::1]:0".parse::<SocketAddr>()?).await?;
                let backend_baz_port = backend_baz.local_addr()?.port();

                let sockfile = tmp_dir.path().join("tarweb-testing.sock");
                let backend_sock = tokio::net::UnixDatagram::bind(&sockfile)?;

                let allow_all = Acl {
                    rules: vec![],
                    default_action: protos::AclAction::Accept,
                };
                // Test config.
                #[allow(clippy::regex_creation_in_loops)]
                let config = Config {
                    max_lifetime: Some(MAX_TEST_CONNECTION_TIME),
                    handshake_timeout: None,
                    rules: vec![
                        Rule {
                            re: regex::Regex::new("foo")?,
                            acl: allow_all.clone(),
                            backend: Backend::Null,
                            timeout: None,
                        },
                        Rule {
                            re: regex::Regex::new("socket")?,
                            acl: allow_all.clone(),
                            backend: Backend::Pass {
                                path: sockfile.clone(),
                                frontend_tls: None,
                                sorry: None,
                            },
                            timeout: None,
                        },
                        Rule {
                            re: regex::Regex::new("bar")?,
                            acl: allow_all.clone(),
                            backend: Backend::Proxy {
                                addr: format!("[::1]:{backend_bar_port}"),
                                proxy_header: false,
                                frontend_tls: None,
                                sorry: None,
                            },
                            timeout: None,
                        },
                    ],
                    default: Rule {
                        acl: allow_all.clone(),
                        re: regex::Regex::new("xxx not used xxx")?,
                        timeout: None,
                        backend: Backend::Proxy {
                            addr: format!("[::1]:{backend_baz_port}"),
                            proxy_header: false,
                            frontend_tls: None,
                            sorry: None,
                        },
                    },
                };
                let _main = tokio::task::spawn(async move {
                    mainloop(Arc::new(config), "", listener, false).await
                });

                let (done_tx1, mut done_rx_bar) = tokio::sync::mpsc::channel::<()>(1);
                let (done_tx2, mut done_rx_baz) = tokio::sync::mpsc::channel::<()>(1);
                let (done_tx3, mut done_rx_sock) = tokio::sync::mpsc::channel::<()>(1);
                let client = async {
                    // Expect failure because our backend immediately disconnects.
                    let _status = tokio::process::Command::new("curl")
                        .arg("-S")
                        .arg("--no-progress-meter")
                        .arg("--connect-to")
                        .arg(format!("foo:443:[::1]:{listener_port}"))
                        .arg("--connect-to")
                        .arg(format!("bar:443:[::1]:{listener_port}"))
                        .arg("--connect-to")
                        .arg(format!("socket:443:[::1]:{listener_port}"))
                        .arg("--connect-to")
                        .arg(format!("bar2:443:[::1]:{listener_port}"))
                        .arg(format!("https://{sni}/"))
                        .spawn()?
                        .wait()
                        .await?;
                    drop(done_tx1);
                    drop(done_tx2);
                    drop(done_tx3);
                    Ok::<(), anyhow::Error>(())
                };
                let backend_bar = async {
                    if sni == "bar" {
                        info!("COVERED: bar");
                        hit_something.store(true, Ordering::Relaxed);
                        tokio::select! {
                            _ = backend_bar.accept() => Ok(()),
                            _ = done_rx_bar.recv() => Err(anyhow!("nobody connected to backend")),
                        }
                    } else {
                        Ok(())
                    }
                };
                let backend_baz = async {
                    if sni == "bar2" {
                        info!("COVERED: default");
                        hit_something.store(true, Ordering::Relaxed);
                        tokio::select! {
                            _ = backend_baz.accept() => Ok(()),
                            _ = done_rx_baz.recv() => Err(anyhow!("nobody connected to backend")),
                        }
                    } else {
                        Ok(())
                    }
                };
                let backend_sock = async {
                    if sni == "socket" {
                        info!("COVERED: socket");
                        hit_something.store(true, Ordering::Relaxed);
                        let mut buf = [0u8; 2048];
                        tokio::select! {
                            _ = backend_sock.recv(&mut buf) => Ok(()),
                            _ = done_rx_sock.recv() => Err(anyhow!("nobody connected to backend")),
                        }
                    } else {
                        Ok(())
                    }
                };
                if sni == "foo" {
                    // Connected to nothing.
                    hit_something.store(true, Ordering::Relaxed);
                }
                tokio::time::timeout(MAX_TEST_CONNECTION_TIME, async {
                    tokio::try_join!(client, backend_bar, backend_baz, backend_sock,)
                })
                .await??;
                assert!(
                    hit_something.load(Ordering::Relaxed),
                    "SNI {sni:?} and opts {curl_opt:?} did not do anything"
                );
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn handshake_timeout_closes_idle_preroute_client() -> Result<()> {
        let allow_all = Acl {
            rules: vec![],
            default_action: protos::AclAction::Accept,
        };
        let listener = tokio::net::TcpListener::bind("[::1]:0".parse::<SocketAddr>()?).await?;
        let listener_port = listener.local_addr()?.port();
        let config = Config {
            max_lifetime: Some(MAX_TEST_CONNECTION_TIME),
            handshake_timeout: Some(tokio::time::Duration::from_millis(50)),
            rules: vec![],
            default: Rule {
                acl: allow_all.clone(),
                timeout: None,
                re: regex::Regex::new("xxx not used xxx")?,
                backend: Backend::Null,
            },
        };
        let _main =
            tokio::task::spawn(
                async move { mainloop(Arc::new(config), "", listener, false).await },
            );

        let mut stream = tokio::net::TcpStream::connect(format!("[::1]:{listener_port}")).await?;
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(MAX_TEST_CONNECTION_TIME, stream.read(&mut buf)).await?;
        match read {
            Ok(0) => Ok(()),
            Ok(n) => Err(anyhow!("idle preroute client read unexpected {n} bytes")),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    #[test]
    fn default_cant_have_regex() -> Result<()> {
        let tmp_dir = tempfile::TempDir::new()?;
        let config_file = tmp_dir.path().join("config.cfg");
        std::fs::write(
            &config_file,
            r#"
default: <
        regex: ""
        backend: <
            null: <>
        >
>
"#,
        )?;
        let c = load_config(config_file.to_str().unwrap(), false);
        assert!(c.is_err(), "Got config: {c:?}");
        Ok(())
    }

    #[tokio::test]
    async fn handshake_timeout_stops_after_proxy_backend_connects() -> Result<()> {
        let allow_all = Acl {
            rules: vec![],
            default_action: protos::AclAction::Accept,
        };
        let listener = tokio::net::TcpListener::bind("[::1]:0".parse::<SocketAddr>()?).await?;
        let listener_port = listener.local_addr()?.port();
        let backend = tokio::net::TcpListener::bind("[::1]:0".parse::<SocketAddr>()?).await?;
        let backend_port = backend.local_addr()?.port();
        let config = Config {
            max_lifetime: Some(MAX_TEST_CONNECTION_TIME),
            handshake_timeout: Some(tokio::time::Duration::from_millis(50)),
            rules: vec![],
            default: Rule {
                acl: allow_all.clone(),
                timeout: None,
                re: regex::Regex::new("xxx not used xxx")?,
                backend: Backend::Proxy {
                    addr: format!("[::1]:{backend_port}"),
                    proxy_header: false,
                    frontend_tls: None,
                    sorry: None,
                },
            },
        };
        let _main =
            tokio::task::spawn(
                async move { mainloop(Arc::new(config), "", listener, false).await },
            );

        let backend = tokio::spawn(async move {
            let (mut stream, _) = backend.accept().await?;
            let mut got = [0u8; 5];
            stream.read_exact(&mut got).await?;
            if got != *b"abcde" {
                return Err(anyhow!("backend got unexpected bytes: {got:?}"));
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
            stream.write_all(b"ok").await?;
            stream.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        });

        let mut stream = tokio::net::TcpStream::connect(format!("[::1]:{listener_port}")).await?;

        // Write invalid TLS records, forcing router to pick the default
        // backend.
        stream.write_all(b"abcde").await?;

        let mut got = Vec::new();
        tokio::time::timeout(MAX_TEST_CONNECTION_TIME, stream.read_to_end(&mut got)).await??;
        backend.await??;
        assert_eq!(got, b"ok");
        Ok(())
    }
}
