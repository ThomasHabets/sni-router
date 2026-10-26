//! HTTP/3 SNI router.
//!
//! This is a UDP proxy for QUIC/HTTP/3. It decrypts QUIC v1 Initial packets
//! using the public Initial secrets, extracts the TLS ClientHello SNI from
//! CRYPTO frames, then forwards the original UDP datagrams unchanged to the
//! selected backend. Later datagrams are routed by learned QUIC connection IDs.

#![allow(clippy::similar_names)]

#[path = "../h3_cid_routes.rs"]
mod cid_routes;
#[path = "../privs.rs"]
mod privs;
#[path = "../resolver.rs"]
mod resolver;
#[path = "../version.rs"]
mod version;

use cid_routes::CidRoutes;
#[path = "../h3_udp.rs"]
mod udp;
use udp::{MAX_DATAGRAM_SIZE, Packet, PacketPool, SendQueue, send_or_queue};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use ring::aead;
use ring::hkdf;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tracing::{debug, error, info, trace, warn};

mod protos {
    include!(concat!(env!("OUT_DIR"), "/sni_router.rs"));
}

const PROTO_DESCRIPTOR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/descriptor.bin"));

const QUIC_VERSION_1: u32 = 0x0000_0001;
const QUIC_PACKET_TYPE_INITIAL: u8 = 0;
const QUIC_V1_INITIAL_SALT: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

const MAX_PENDING_DATAGRAMS: usize = 32;
const MAX_PENDING_BYTES: usize = 128 * 1024;

/// HTTP/3 SNI router.
#[derive(clap::Parser)]
#[clap(version)]
struct Opt {
    /// Verbosity level. Can be error, warn info, debug, or trace.
    #[arg(long, short, default_value = "info")]
    verbose: String,

    /// UDP address to listen to. Defaults to [::]:443.
    #[arg(long, short, default_value = "[::]:443")]
    listen: SocketAddr,

    /// Restrict router to only be able to read under this directory.
    #[arg(long, default_value = "/")]
    restrict_dirs: Vec<std::path::PathBuf>,

    /// Drop idle connection-id routing state after this many milliseconds.
    #[arg(long, default_value_t = 300_000)]
    idle_timeout_ms: u64,

    /// Asciiproto config. For this binary, proxy.addr is interpreted as a UDP backend.
    #[arg(long, short)]
    config: String,
}

#[derive(Debug, Clone)]
enum Backend {
    Null,
    Udp { addr: SocketAddr },
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

#[derive(Debug, Clone)]
struct Rule {
    re: regex::Regex,
    backend: Backend,
    acl: Acl,
    timeout: Option<Duration>,
}

#[derive(Debug)]
struct Config {
    max_lifetime: Option<Duration>,
    handshake_timeout: Option<Duration>,
    rules: Vec<Rule>,
    default: Rule,
}

#[derive(Clone, Debug)]
struct Route {
    backend: Backend,
    timeout: Option<Duration>,
    sni: Option<String>,
}

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
            action: rule.action(),
        });
    }
    Ok(Acl {
        rules,
        default_action: pb.default_action(),
    })
}

async fn resolve_one_addr(addr: &str) -> Result<SocketAddr> {
    resolver::lookup_host(addr)
        .await
        .with_context(|| format!("resolving backend address {addr:?}"))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("backend address {addr:?} resolved to no socket addresses"))
}

async fn load_backend(pb: &protos::Backend) -> Result<Backend> {
    if pb.frontend_tls.is_some() {
        return Err(anyhow!(
            "frontend_tls is TCP-only and is not supported by sni-router-h3"
        ));
    }
    if pb.sorry.is_some() {
        return Err(anyhow!(
            "sorry backends are TCP-only and are not supported by sni-router-h3"
        ));
    }
    match pb
        .backend_type
        .as_ref()
        .ok_or_else(|| anyhow!("backend missing actual backend"))?
    {
        protos::backend::BackendType::Null(_) => Ok(Backend::Null),
        protos::backend::BackendType::Proxy(proxy) => {
            if proxy.proxy_header {
                return Err(anyhow!(
                    "proxy_header is TCP-only and is not supported by sni-router-h3"
                ));
            }
            Ok(Backend::Udp {
                addr: resolve_one_addr(&proxy.addr).await?,
            })
        }
        protos::backend::BackendType::Pass(_) => Err(anyhow!(
            "pass backends are TCP-only and are not supported by sni-router-h3"
        )),
    }
}

async fn load_rule(rule: &protos::Rule, is_default: bool) -> Result<Rule> {
    let re = if is_default {
        if let Some(r) = rule.regex.as_ref() {
            return Err(anyhow!("default rule can't have regex. Had {r}"));
        }
        ""
    } else {
        rule.regex
            .as_ref()
            .ok_or_else(|| anyhow!("No regex supplied in rule"))?
    };
    Ok(Rule {
        re: if is_default {
            regex::Regex::new(re)?
        } else {
            compile_full_match(re)?
        },
        acl: rule.acl.as_ref().map_or(
            Ok(Acl {
                rules: vec![],
                default_action: protos::AclAction::Accept,
            }),
            load_acl,
        )?,
        timeout: (rule.max_lifetime_ms > 0).then(|| Duration::from_millis(rule.max_lifetime_ms)),
        backend: load_backend(
            rule.backend
                .as_ref()
                .ok_or_else(|| anyhow!("rule missing backend"))?,
        )
        .await?,
    })
}

async fn load_config(filename: &str) -> Result<Config> {
    let pool = prost_reflect::DescriptorPool::decode(PROTO_DESCRIPTOR)?;
    let md = pool
        .get_message_by_name("sni_router.SNIConfig")
        .ok_or_else(|| anyhow!("Unable to reflect SNIConfig"))?;
    let cwd = std::env::current_dir()
        .map(|c| c.display().to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    let txt = std::fs::read_to_string(filename)
        .with_context(|| format!("opening {filename:?} from cwd {cwd:?}"))?;
    let dyn_msg = prost_reflect::DynamicMessage::parse_text_format(md, &txt)?;
    let protocfg: protos::SniConfig = dyn_msg.transcode_to()?;

    let mut config = Config {
        max_lifetime: (protocfg.max_lifetime_ms > 0)
            .then(|| Duration::from_millis(protocfg.max_lifetime_ms)),
        handshake_timeout: (protocfg.handshake_timeout_ms > 0)
            .then(|| Duration::from_millis(protocfg.handshake_timeout_ms)),
        rules: vec![],
        default: {
            let rule = load_rule(
                &protocfg
                    .default
                    .ok_or_else(|| anyhow!("default rule is missing"))?,
                true,
            )
            .await?;
            if !rule.re.as_str().is_empty() {
                return Err(anyhow!("default rule can't have regex"));
            }
            rule
        },
    };
    for rule in protocfg.rules {
        config.rules.push(load_rule(&rule, false).await?);
    }
    Ok(config)
}

/// Compile a routing regex that must match the entire hostname.
fn compile_full_match(pattern: &str) -> Result<regex::Regex> {
    // Validate before wrapping so the pattern cannot close the added group.
    regex::Regex::new(pattern)?;
    Ok(
        regex::Regex::new(&format!(r"\A(?:{pattern})\z")).or_else(|_| {
            // A trailing free-spacing comment can swallow the closing group.
            regex::Regex::new(&format!("\\A(?:{pattern}\n)\\z"))
        })?,
    )
}

fn peer_ip_v6(peer: SocketAddr) -> Ipv6Addr {
    match peer.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

fn normalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), v6.port()))
            .unwrap_or(SocketAddr::V6(v6)),
        SocketAddr::V4(_) => addr,
    }
}

fn socket_addrs_equal(left: SocketAddr, right: SocketAddr) -> bool {
    normalize_socket_addr(left) == normalize_socket_addr(right)
}

fn send_addr_for_socket(socket: &UdpSocket, addr: SocketAddr) -> Result<SocketAddr> {
    let local = socket
        .local_addr()
        .context("getting UDP socket local addr")?;
    match (local, addr) {
        (SocketAddr::V6(_), SocketAddr::V4(v4)) => Ok(SocketAddr::V6(SocketAddrV6::new(
            v4.ip().to_ipv6_mapped(),
            v4.port(),
            0,
            0,
        ))),
        (SocketAddr::V4(_), SocketAddr::V6(v6)) if v6.ip().to_ipv4_mapped().is_none() => Err(
            anyhow!("cannot send to IPv6 address {addr} from IPv4 UDP listener {local}"),
        ),
        (_, addr) => Ok(addr),
    }
}

struct ProxySockets {
    client: Arc<UdpSocket>,
    writer: Option<SendQueue>,
}

impl ProxySockets {
    fn new(client_listen: SocketAddr) -> Result<Self> {
        Ok(Self {
            client: Arc::new(
                bind_udp_socket(client_listen, true)
                    .with_context(|| format!("listening on UDP {client_listen}"))?,
            ),
            writer: None,
        })
    }

    fn client_addr(&self) -> Result<SocketAddr> {
        self.client
            .local_addr()
            .context("getting client UDP socket addr")
    }

    fn send_to_client(&mut self, packet: &[u8], addr: SocketAddr) -> Result<()> {
        let addr = send_addr_for_socket(&self.client, addr)?;
        send_or_queue(&self.client, &mut self.writer, packet, Some(addr))
    }
}

struct BackendDatagram {
    conn_id: usize,
    packet: Packet,
}

fn acl_action(acl: &Acl, peer: &Ipv6Addr) -> protos::AclAction {
    for rule in &acl.rules {
        if rule.source.contains(peer) {
            return rule.action;
        }
    }
    acl.default_action
}

fn min_timeout(a: Option<Duration>, b: Option<Duration>) -> Option<Duration> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}

/// Extract SNI host_name from a TLS ClientHello handshake message.
fn extract_tls_sni(clienthello: &[u8]) -> Result<Option<String>> {
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

    if body.len() < i + 2 {
        bail!("missing cipher_suites length");
    }
    let cs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + cs_len || !cs_len.is_multiple_of(2) {
        bail!("invalid cipher_suites vector");
    }
    i += cs_len;

    if body.len() < i + 1 {
        bail!("missing compression_methods length");
    }
    let cmethod_len = body[i] as usize;
    i += 1;
    if body.len() < i + cmethod_len {
        bail!("invalid compression_methods vector");
    }
    i += cmethod_len;

    if i == body.len() {
        return Ok(None);
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
                    return Ok(Some(
                        String::from_utf8_lossy(&ext[k..k + host_len]).to_string(),
                    ));
                }
                k += host_len;
            }
            return Ok(None);
        }
        j += elen;
    }

    Ok(None)
}

#[derive(Clone, Debug)]
struct LongPacketCids {
    version: u32,
    packet_type: u8,
    dcid: Vec<u8>,
    scid: Vec<u8>,
}

#[derive(Debug)]
struct InitialHeader {
    cids: LongPacketCids,
    packet_number_offset: usize,
    packet_end: usize,
}

#[derive(Debug)]
struct DecryptedInitial {
    dcid: Vec<u8>,
    scid: Vec<u8>,
    payload: Vec<u8>,
}

#[derive(Clone, Copy)]
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

struct InitialKeyBytes {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

struct InitialKeys {
    open: aead::LessSafeKey,
    hp: aead::quic::HeaderProtectionKey,
    iv: [u8; 12],
}

fn read_varint_at(buf: &[u8], offset: usize) -> Result<(u64, usize)> {
    let first = *buf
        .get(offset)
        .ok_or_else(|| anyhow!("missing QUIC varint"))?;
    let len = 1usize << (first >> 6);
    if buf.len() < offset + len {
        bail!("truncated QUIC varint");
    }
    let mut value = u64::from(first & 0x3f);
    for b in &buf[offset + 1..offset + len] {
        value = (value << 8) | u64::from(*b);
    }
    Ok((value, len))
}

fn read_varint(buf: &[u8], offset: &mut usize) -> Result<u64> {
    let (value, len) = read_varint_at(buf, *offset)?;
    *offset += len;
    Ok(value)
}

fn parse_long_packet_cids(packet: &[u8]) -> Result<Option<LongPacketCids>> {
    if packet.first().is_none_or(|first| first & 0x80 == 0) {
        return Ok(None);
    }
    if packet.len() < 7 {
        bail!("truncated QUIC long header");
    }
    let first = packet[0];
    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    let packet_type = (first & 0x30) >> 4;
    let mut i = 5usize;
    let dcid_len = packet[i] as usize;
    i += 1;
    if packet.len() < i + dcid_len + 1 {
        bail!("truncated QUIC destination connection ID");
    }
    let dcid = packet[i..i + dcid_len].to_vec();
    i += dcid_len;
    let scid_len = packet[i] as usize;
    i += 1;
    if packet.len() < i + scid_len {
        bail!("truncated QUIC source connection ID");
    }
    let scid = packet[i..i + scid_len].to_vec();
    Ok(Some(LongPacketCids {
        version,
        packet_type,
        dcid,
        scid,
    }))
}

fn parse_initial_header(packet: &[u8]) -> Result<InitialHeader> {
    let cids =
        parse_long_packet_cids(packet)?.ok_or_else(|| anyhow!("not a QUIC long-header packet"))?;
    if cids.version != QUIC_VERSION_1 {
        bail!("unsupported QUIC version {:#x}", cids.version);
    }
    if cids.packet_type != QUIC_PACKET_TYPE_INITIAL {
        bail!("not a QUIC Initial packet");
    }

    let mut i = 5 + 1 + cids.dcid.len() + 1 + cids.scid.len();
    let (token_len, token_len_len) = read_varint_at(packet, i)?;
    i += token_len_len;
    let token_len = usize::try_from(token_len).context("QUIC token length too large")?;
    if packet.len() < i + token_len {
        bail!("truncated QUIC Initial token");
    }
    i += token_len;
    let (packet_len, packet_len_len) = read_varint_at(packet, i)?;
    i += packet_len_len;
    let packet_len = usize::try_from(packet_len).context("QUIC Initial packet length too large")?;
    let packet_end = i
        .checked_add(packet_len)
        .ok_or_else(|| anyhow!("QUIC Initial packet length overflow"))?;
    if packet_end > packet.len() {
        bail!("truncated QUIC Initial packet payload");
    }
    Ok(InitialHeader {
        cids,
        packet_number_offset: i,
        packet_end,
    })
}

fn hkdf_expand_label(secret: &hkdf::Prk, label: &[u8], len: usize) -> Result<Vec<u8>> {
    let full_label_len = b"tls13 ".len() + label.len();
    if full_label_len > u8::MAX as usize {
        bail!("HKDF label too long");
    }
    let len_u16 = u16::try_from(len).context("HKDF output length too large")?;
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1);
    info.extend_from_slice(&len_u16.to_be_bytes());
    info.push(u8::try_from(full_label_len)?);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);

    let mut out = vec![0u8; len];
    secret
        .expand(&[&info], HkdfLen(len))
        .map_err(|_| anyhow!("HKDF expand failed"))?
        .fill(&mut out)
        .map_err(|_| anyhow!("HKDF fill failed"))?;
    Ok(out)
}

fn initial_key_bytes(dcid: &[u8]) -> Result<InitialKeyBytes> {
    let initial_secret = hkdf::Salt::new(hkdf::HKDF_SHA256, QUIC_V1_INITIAL_SALT).extract(dcid);
    let client_initial_secret = hkdf_expand_label(&initial_secret, b"client in", 32)?;
    let client_initial_secret = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client_initial_secret);

    let key = hkdf_expand_label(&client_initial_secret, b"quic key", 16)?;
    let iv = hkdf_expand_label(&client_initial_secret, b"quic iv", 12)?;
    let hp = hkdf_expand_label(&client_initial_secret, b"quic hp", 16)?;
    Ok(InitialKeyBytes {
        key: key.try_into().expect("quic key length is fixed"),
        iv: iv.try_into().expect("quic iv length is fixed"),
        hp: hp.try_into().expect("quic hp length is fixed"),
    })
}

fn initial_keys(dcid: &[u8]) -> Result<InitialKeys> {
    let bytes = initial_key_bytes(dcid)?;
    let open = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &bytes.key)
            .map_err(|_| anyhow!("failed to create QUIC Initial AEAD key"))?,
    );
    let hp = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &bytes.hp)
        .map_err(|_| anyhow!("failed to create QUIC Initial header protection key"))?;
    Ok(InitialKeys {
        open,
        hp,
        iv: bytes.iv,
    })
}

fn packet_nonce(iv: &[u8; 12], packet_number: u64) -> aead::Nonce {
    let mut nonce = *iv;
    for (dst, src) in nonce[4..].iter_mut().zip(packet_number.to_be_bytes()) {
        *dst ^= src;
    }
    aead::Nonce::assume_unique_for_key(nonce)
}

fn decrypt_initial_packet(packet: &[u8]) -> Result<DecryptedInitial> {
    let header = parse_initial_header(packet)?;
    let keys = initial_keys(&header.cids.dcid)?;

    let sample_offset = header.packet_number_offset + 4;
    if header.packet_end < sample_offset + aead::quic::AES_128.sample_len() {
        bail!("QUIC Initial packet too short for header protection sample");
    }
    let mask = keys
        .hp
        .new_mask(&packet[sample_offset..sample_offset + aead::quic::AES_128.sample_len()])
        .map_err(|_| anyhow!("QUIC Initial header protection failed"))?;

    let first = packet[0] ^ (mask[0] & 0x0f);
    let packet_number_len = usize::from(first & 0x03) + 1;
    let packet_number_end = header.packet_number_offset + packet_number_len;
    if packet_number_end > header.packet_end {
        bail!("truncated QUIC Initial packet number");
    }

    let mut packet_number = 0u64;
    let mut associated_data = packet[..packet_number_end].to_vec();
    associated_data[0] = first;
    for (i, byte) in associated_data[header.packet_number_offset..]
        .iter_mut()
        .enumerate()
    {
        *byte ^= mask[i + 1];
        packet_number = (packet_number << 8) | u64::from(*byte);
    }

    let mut payload = packet[packet_number_end..header.packet_end].to_vec();
    let plaintext_len = keys
        .open
        .open_in_place(
            packet_nonce(&keys.iv, packet_number),
            aead::Aad::from(&associated_data),
            &mut payload,
        )
        .map_err(|_| anyhow!("QUIC Initial decrypt failed"))?
        .len();
    payload.truncate(plaintext_len);

    Ok(DecryptedInitial {
        dcid: header.cids.dcid,
        scid: header.cids.scid,
        payload,
    })
}

fn read_crypto_frames(payload: &[u8]) -> Result<Vec<(u64, &[u8])>> {
    let mut frames = Vec::new();
    let mut i = 0usize;
    while i < payload.len() {
        let frame_type = read_varint(payload, &mut i)?;
        match frame_type {
            0x00 => {}
            0x01 => {}
            0x02 | 0x03 => {
                skip_ack_frame(payload, &mut i, frame_type == 0x03)?;
            }
            0x06 => {
                let offset = read_varint(payload, &mut i)?;
                let len = usize::try_from(read_varint(payload, &mut i)?)
                    .context("CRYPTO frame length too large")?;
                if payload.len() < i + len {
                    bail!("truncated CRYPTO frame");
                }
                frames.push((offset, &payload[i..i + len]));
                i += len;
            }
            0x1c => {
                skip_transport_close_frame(payload, &mut i)?;
            }
            0x1d => {
                skip_application_close_frame(payload, &mut i)?;
            }
            _ => bail!("unexpected frame type {frame_type:#x} in Initial packet"),
        }
    }
    Ok(frames)
}

fn skip_ack_frame(payload: &[u8], i: &mut usize, has_ecn: bool) -> Result<()> {
    let _largest_acknowledged = read_varint(payload, i)?;
    let _ack_delay = read_varint(payload, i)?;
    let ack_range_count = read_varint(payload, i)?;
    let _first_ack_range = read_varint(payload, i)?;
    for _ in 0..ack_range_count {
        let _gap = read_varint(payload, i)?;
        let _ack_range_length = read_varint(payload, i)?;
    }
    if has_ecn {
        let _ect0_count = read_varint(payload, i)?;
        let _ect1_count = read_varint(payload, i)?;
        let _ecn_ce_count = read_varint(payload, i)?;
    }
    Ok(())
}

fn skip_transport_close_frame(payload: &[u8], i: &mut usize) -> Result<()> {
    let _error_code = read_varint(payload, i)?;
    let _frame_type = read_varint(payload, i)?;
    let reason_len =
        usize::try_from(read_varint(payload, i)?).context("CONNECTION_CLOSE reason too large")?;
    if payload.len() < *i + reason_len {
        bail!("truncated CONNECTION_CLOSE reason");
    }
    *i += reason_len;
    Ok(())
}

fn skip_application_close_frame(payload: &[u8], i: &mut usize) -> Result<()> {
    let _error_code = read_varint(payload, i)?;
    let reason_len =
        usize::try_from(read_varint(payload, i)?).context("CONNECTION_CLOSE reason too large")?;
    if payload.len() < *i + reason_len {
        bail!("truncated CONNECTION_CLOSE reason");
    }
    *i += reason_len;
    Ok(())
}

#[derive(Default, Debug)]
struct CryptoReassembly {
    bytes: Vec<u8>,
    fragments: BTreeMap<u64, Vec<u8>>,
}

impl CryptoReassembly {
    fn insert(&mut self, offset: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let next = u64::try_from(self.bytes.len()).expect("usize fits in u64");
        if offset > next {
            if self
                .fragments
                .get(&offset)
                .is_none_or(|old| old.len() < data.len())
            {
                self.fragments.insert(offset, data.to_vec());
            }
            return;
        }
        self.append(offset, data);
        while self.fragments.first_key_value().is_some_and(|(offset, _)| {
            *offset <= u64::try_from(self.bytes.len()).expect("usize fits in u64")
        }) {
            let (offset, fragment) = self.fragments.pop_first().expect("fragment available");
            self.append(offset, &fragment);
        }
    }

    fn append(&mut self, offset: u64, data: &[u8]) {
        let next = u64::try_from(self.bytes.len()).expect("usize fits in u64");
        let skip = usize::try_from(next - offset).unwrap_or(usize::MAX);
        if let Some(suffix) = data.get(skip..) {
            self.bytes.extend_from_slice(suffix);
        }
    }

    fn clienthello(&self) -> Result<Option<&[u8]>> {
        if self.bytes.len() < 4 {
            return Ok(None);
        }
        if self.bytes[0] != 1 {
            bail!(
                "first TLS handshake message in QUIC Initial is {}, expected ClientHello",
                self.bytes[0]
            );
        }
        let body_len = ((self.bytes[1] as usize) << 16)
            | ((self.bytes[2] as usize) << 8)
            | (self.bytes[3] as usize);
        let needed = 4 + body_len;
        if self.bytes.len() < needed {
            return Ok(None);
        }
        Ok(Some(&self.bytes[..needed]))
    }
}

#[derive(Debug)]
struct PendingConnection {
    client_addr: SocketAddr,
    initial_dcid: Vec<u8>,
    client_cids: HashSet<Vec<u8>>,
    datagrams: Vec<Vec<u8>>,
    buffered_bytes: usize,
    crypto: CryptoReassembly,
    created: Instant,
    last_seen: Instant,
}

impl PendingConnection {
    fn new(client_addr: SocketAddr, initial_dcid: Vec<u8>, now: Instant) -> Self {
        Self {
            client_addr,
            initial_dcid,
            client_cids: HashSet::new(),
            datagrams: Vec::new(),
            buffered_bytes: 0,
            crypto: CryptoReassembly::default(),
            created: now,
            last_seen: now,
        }
    }

    fn push_datagram(&mut self, datagram: Vec<u8>) -> Result<()> {
        if self.datagrams.len() >= MAX_PENDING_DATAGRAMS {
            bail!("too many pending Initial datagrams");
        }
        let new_buffered_bytes = self
            .buffered_bytes
            .checked_add(datagram.len())
            .ok_or_else(|| anyhow!("pending datagram byte count overflow"))?;
        if new_buffered_bytes > MAX_PENDING_BYTES {
            bail!("too many pending Initial bytes");
        }
        self.buffered_bytes = new_buffered_bytes;
        self.datagrams.push(datagram);
        Ok(())
    }
}

struct Connection {
    backend_socket: Arc<UdpSocket>,
    backend_writer: Option<SendQueue>,
    backend_task: tokio::task::JoinHandle<()>,
    client_addr: SocketAddr,
    cids: HashSet<Vec<u8>>,
    created: Instant,
    last_seen: Instant,
    deadline: Option<Instant>,
    sni: Option<String>,
}

struct Router {
    config: Arc<Config>,
    packet_pool: Arc<PacketPool>,
    idle_timeout: Duration,
    next_connection_id: usize,
    connections: HashMap<usize, Connection>,
    cid_routes: CidRoutes,
    client_routes: HashMap<SocketAddr, usize>,
    pending: HashMap<(SocketAddr, Vec<u8>), PendingConnection>,
}

impl Router {
    fn new(config: Arc<Config>, idle_timeout: Duration) -> Self {
        Self {
            config,
            packet_pool: Arc::new(PacketPool::default()),
            idle_timeout,
            next_connection_id: 0,
            connections: HashMap::new(),
            cid_routes: CidRoutes::default(),
            client_routes: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    fn set_config(&mut self, config: Arc<Config>) {
        self.config = config;
    }

    fn route_for_sni(&self, peer: SocketAddr, sni: Option<String>) -> Result<Route> {
        let peer = peer_ip_v6(peer);
        if let Some(sni_ref) = sni.as_deref() {
            for rule in &self.config.rules {
                if !rule.re.is_match(sni_ref) {
                    continue;
                }
                match acl_action(&rule.acl, &peer) {
                    protos::AclAction::Unspecified => {
                        return Err(anyhow!("unspecified ACL action"));
                    }
                    protos::AclAction::Continue => continue,
                    protos::AclAction::Drop => {
                        return Ok(Route {
                            backend: Backend::Null,
                            timeout: min_timeout(self.config.max_lifetime, rule.timeout),
                            sni,
                        });
                    }
                    protos::AclAction::Accept => {
                        return Ok(Route {
                            backend: rule.backend.clone(),
                            timeout: min_timeout(self.config.max_lifetime, rule.timeout),
                            sni,
                        });
                    }
                }
            }
        }
        Ok(Route {
            backend: match acl_action(&self.config.default.acl, &peer) {
                protos::AclAction::Accept => self.config.default.backend.clone(),
                protos::AclAction::Unspecified => bail!("unspecified default ACL action"),
                protos::AclAction::Drop | protos::AclAction::Continue => Backend::Null,
            },
            timeout: min_timeout(self.config.max_lifetime, self.config.default.timeout),
            sni,
        })
    }

    async fn handle_datagram(
        &mut self,
        peer: SocketAddr,
        packet: &[u8],
        backend_events: &tokio::sync::mpsc::Sender<BackendDatagram>,
    ) -> Result<()> {
        let (long, conn_id) = match self.packet_connection_id(packet) {
            Ok(route) => route,
            Err(e) => {
                debug!("dropping datagram with malformed QUIC header from {peer}: {e}");
                return Ok(());
            }
        };
        trace!("Got packet with CIDS {long:?}");

        let conn_id = conn_id.or_else(|| {
            long.is_none()
                .then(|| {
                    self.client_routes
                        .get(&normalize_socket_addr(peer))
                        .copied()
                })
                .flatten()
        });

        let Some(conn_id) = conn_id else {
            return self
                .handle_unrouted_client_datagram(peer, packet, long, backend_events)
                .await;
        };

        let Some(conn) = self.connections.get(&conn_id) else {
            return Ok(());
        };
        if socket_addrs_equal(peer, conn.client_addr) {
            self.forward_established_client_datagram(conn_id, peer, packet, long)
                .await
        } else {
            debug!(
                "dropping client datagram for connection id={conn_id} from unexpected peer {peer}; client={}",
                conn.client_addr
            );
            Ok(())
        }
    }

    fn packet_connection_id(
        &self,
        packet: &[u8],
    ) -> Result<(Option<LongPacketCids>, Option<usize>)> {
        let long = parse_long_packet_cids(packet)?;
        let conn_id = if let Some(long) = long.as_ref() {
            self.cid_routes.get(&long.dcid).copied()
        } else {
            self.match_short_header_route(packet)
        };
        Ok((long, conn_id))
    }

    async fn forward_established_backend_datagram(
        &mut self,
        sockets: &mut ProxySockets,
        conn_id: usize,
        packet: Packet,
        long: Option<LongPacketCids>,
    ) -> Result<()> {
        let new_cid = long.and_then(|long| (!long.scid.is_empty()).then_some(long.scid));
        let client_addr = {
            let Some(conn) = self.connections.get_mut(&conn_id) else {
                return Ok(());
            };
            conn.last_seen = Instant::now();
            conn.client_addr
        };
        if let Some(cid) = new_cid {
            self.add_cid_route(conn_id, cid);
        }
        sockets.send_to_client(&packet, client_addr)?;
        trace!("forwarded backend datagram for connection id={conn_id}");
        Ok(())
    }

    async fn handle_backend_datagram(
        &mut self,
        sockets: &mut ProxySockets,
        datagram: BackendDatagram,
    ) -> Result<()> {
        let long = match parse_long_packet_cids(&datagram.packet) {
            Ok(long) => long,
            Err(e) => {
                debug!(
                    "dropping backend datagram for connection id={} with malformed QUIC header: {e}",
                    datagram.conn_id
                );
                return Ok(());
            }
        };
        trace!(
            "Got backend packet for connection id={} with CIDS {long:?}",
            datagram.conn_id
        );
        self.forward_established_backend_datagram(sockets, datagram.conn_id, datagram.packet, long)
            .await
    }

    async fn handle_unrouted_client_datagram(
        &mut self,
        peer: SocketAddr,
        packet: &[u8],
        long: Option<LongPacketCids>,
        backend_events: &tokio::sync::mpsc::Sender<BackendDatagram>,
    ) -> Result<()> {
        let Some(long) = long else {
            debug!("dropping short-header client datagram from {peer} with unknown connection ID");
            return Ok(());
        };
        if long.version != QUIC_VERSION_1 || long.packet_type != QUIC_PACKET_TYPE_INITIAL {
            debug!(
                "dropping unrouted long-header client datagram from {peer}: version={:#x} type={}",
                long.version, long.packet_type
            );
            return Ok(());
        }

        let decrypted = match decrypt_initial_packet(packet) {
            Ok(decrypted) => decrypted,
            Err(e) => {
                debug!("dropping undecryptable QUIC Initial from {peer}: {e}");
                return Ok(());
            }
        };
        let crypto_frames = match read_crypto_frames(&decrypted.payload) {
            Ok(frames) => frames,
            Err(e) => {
                debug!("dropping QUIC Initial with unparsable frames from {peer}: {e}");
                return Ok(());
            }
        };

        let pending_key = (peer, decrypted.dcid.clone());
        let now = Instant::now();
        let clienthello = {
            let pending = self
                .pending
                .entry(pending_key.clone())
                .or_insert_with(|| PendingConnection::new(peer, decrypted.dcid.clone(), now));
            pending.last_seen = now;
            if !decrypted.scid.is_empty() {
                pending.client_cids.insert(decrypted.scid);
            }
            pending.push_datagram(packet.to_vec())?;
            for (offset, data) in crypto_frames {
                pending.crypto.insert(offset, data);
            }
            pending.crypto.clienthello()
        }?;

        let Some(clienthello) = clienthello else {
            trace!("waiting for more QUIC Initial CRYPTO data from {peer}");
            return Ok(());
        };

        let sni = match extract_tls_sni(clienthello) {
            Ok(sni) => sni,
            Err(e) => {
                warn!("using default backend for {peer} because ClientHello SNI parse failed: {e}");
                None
            }
        };
        let route = self.route_for_sni(peer, sni)?;
        let Some(pending) = self.pending.remove(&pending_key) else {
            return Ok(());
        };
        self.establish_and_flush(pending, route, backend_events)
            .await
    }

    async fn forward_established_client_datagram(
        &mut self,
        conn_id: usize,
        peer: SocketAddr,
        packet: &[u8],
        long: Option<LongPacketCids>,
    ) -> Result<()> {
        let new_cid = long.and_then(|long| (!long.scid.is_empty()).then_some(long.scid));
        let old_client_addr = {
            let Some(conn) = self.connections.get_mut(&conn_id) else {
                return Ok(());
            };
            let old_client_addr = conn.client_addr;
            conn.client_addr = peer;
            conn.last_seen = Instant::now();
            send_or_queue(&conn.backend_socket, &mut conn.backend_writer, packet, None)?;
            old_client_addr
        };
        let old_client_key = normalize_socket_addr(old_client_addr);
        let new_client_key = normalize_socket_addr(peer);
        if old_client_key != new_client_key {
            self.client_routes.remove(&old_client_key);
        }
        self.client_routes.insert(new_client_key, conn_id);
        if let Some(cid) = new_cid {
            self.add_cid_route(conn_id, cid);
        }
        Ok(())
    }

    async fn establish_and_flush(
        &mut self,
        pending: PendingConnection,
        route: Route,
        backend_events: &tokio::sync::mpsc::Sender<BackendDatagram>,
    ) -> Result<()> {
        let Backend::Udp { addr } = route.backend else {
            debug!(
                "dropping QUIC connection from {} with SNI {:?}: null backend",
                pending.client_addr, route.sni
            );
            return Ok(());
        };

        let conn_id = self.next_connection_id;
        self.next_connection_id += 1;
        let now = Instant::now();
        let deadline = route.timeout.map(|timeout| now + timeout);
        let backend_socket = Arc::new(connect_backend_socket(addr).await?);
        let backend_socket_addr = backend_socket
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|e| format!("<unknown: {e}>"));
        let backend_task = spawn_backend_reader(
            conn_id,
            backend_socket.clone(),
            backend_events.clone(),
            self.packet_pool.clone(),
        );
        let mut cids = HashSet::new();
        if !pending.initial_dcid.is_empty() {
            cids.insert(pending.initial_dcid.clone());
        }
        for cid in &pending.client_cids {
            if !cid.is_empty() {
                cids.insert(cid.clone());
            }
        }
        self.connections.insert(
            conn_id,
            Connection {
                backend_socket: backend_socket.clone(),
                backend_writer: None,
                backend_task,
                client_addr: pending.client_addr,
                cids: cids.clone(),
                created: now,
                last_seen: now,
                deadline,
                sni: route.sni.clone(),
            },
        );
        for cid in cids {
            self.cid_routes.insert(cid, conn_id);
        }
        self.client_routes
            .insert(normalize_socket_addr(pending.client_addr), conn_id);
        info!(
            "routing QUIC connection id={conn_id} peer={} sni={:?} backend={addr} backend_socket={backend_socket_addr}",
            pending.client_addr, route.sni
        );
        let conn = self
            .connections
            .get_mut(&conn_id)
            .expect("connection inserted");
        for datagram in pending.datagrams {
            send_or_queue(&backend_socket, &mut conn.backend_writer, &datagram, None)
                .context("flushing pending Initial datagram to backend")?;
        }
        Ok(())
    }

    fn add_cid_route(&mut self, conn_id: usize, cid: Vec<u8>) {
        if cid.is_empty() {
            return;
        }
        if let Some(conn) = self.connections.get_mut(&conn_id)
            && conn.cids.insert(cid.clone())
        {
            self.cid_routes.insert(cid, conn_id);
        }
    }

    fn match_short_header_route(&self, packet: &[u8]) -> Option<usize> {
        if packet.first().is_none_or(|first| first & 0x80 != 0) {
            return None;
        }
        self.cid_routes.match_prefix(&packet[1..])
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .connections
            .iter()
            .filter_map(|(conn_id, conn)| {
                let idle = now.duration_since(conn.last_seen) >= self.idle_timeout;
                let lifetime = conn.deadline.is_some_and(|deadline| now >= deadline);
                (idle || lifetime).then_some(*conn_id)
            })
            .collect();
        for conn_id in expired {
            if let Some(conn) = self.connections.remove(&conn_id) {
                debug!(
                    "forgetting QUIC connection id={conn_id} sni={:?} age_ms={} idle_ms={}",
                    conn.sni,
                    now.duration_since(conn.created).as_millis(),
                    now.duration_since(conn.last_seen).as_millis()
                );
                for cid in conn.cids {
                    self.cid_routes.remove(&cid);
                }
                let client = normalize_socket_addr(conn.client_addr);
                if self.client_routes.get(&client) == Some(&conn_id) {
                    self.client_routes.remove(&client);
                }
                conn.backend_task.abort();
            }
        }

        let pending_timeout = self
            .config
            .handshake_timeout
            .unwrap_or(self.idle_timeout)
            .min(self.idle_timeout);
        self.pending.retain(|_, pending| {
            let keep = now.duration_since(pending.last_seen) < pending_timeout
                && now.duration_since(pending.created) < pending_timeout;
            if !keep {
                debug!(
                    "dropping pending QUIC Initial state from {} after {} ms",
                    pending.client_addr,
                    now.duration_since(pending.created).as_millis()
                );
            }
            keep
        });
    }
}

async fn connect_backend_socket(addr: SocketAddr) -> Result<UdpSocket> {
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let socket = bind_udp_socket(bind_addr, false)
        .with_context(|| format!("binding backend UDP socket for {addr}"))?;
    socket
        .connect(addr)
        .await
        .with_context(|| format!("connecting backend UDP socket to {addr}"))?;
    Ok(socket)
}

fn spawn_backend_reader(
    conn_id: usize,
    socket: Arc<UdpSocket>,
    backend_events: tokio::sync::mpsc::Sender<BackendDatagram>,
    pool: Arc<PacketPool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(e) = socket.readable().await {
                warn!("backend UDP readiness failed for connection id={conn_id}: {e:#}");
                break;
            }
            // Wait for channel space before checking out a large receive buffer.
            let Ok(permit) = backend_events.reserve().await else {
                break;
            };
            let mut packet = pool.acquire();
            match socket.try_recv(packet.buffer_mut()) {
                Ok(len) => {
                    packet.set_len(len);
                    permit.send(BackendDatagram { conn_id, packet });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    warn!("backend UDP recv failed for connection id={conn_id}: {e:#}");
                    break;
                }
            }
        }
    })
}

async fn mainloop(
    mut sockets: ProxySockets,
    mut router: Router,
    config_filename: &str,
) -> Result<()> {
    let mut client_buf = vec![0u8; MAX_DATAGRAM_SIZE];
    let (backend_tx, mut backend_rx) = tokio::sync::mpsc::channel::<BackendDatagram>(1024);
    let mut hups = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("Registering SIGHUP");
    let mut cleanup = tokio::time::interval(Duration::from_secs(30));
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            r = sockets.client.recv_from(&mut client_buf) => {
                let (n, peer) = match r {
                    Ok(r) => r,
                    Err(e) => {
                        error!("client UDP recv failed: {e:#}");
                        continue;
                    }
                };
                let packet = &client_buf[..n];
                if let Err(e) = router.handle_datagram(peer, packet, &backend_tx).await {
                    warn!("handling client UDP datagram from {peer}: {e:#}");
                }
            }
            datagram = backend_rx.recv() => {
                let Some(datagram) = datagram else {
                    return Err(anyhow!("backend datagram channel closed"));
                };
                if let Err(e) = router.handle_backend_datagram(&mut sockets, datagram).await {
                    warn!("handling backend UDP datagram: {e:#}");
                }
            }
            _ = hups.recv() => {
                let cwd = std::env::current_dir()
                    .map(|c| c.display().to_string())
                    .unwrap_or_else(|_| "<unknown>".to_string());
                info!("Got SIGHUP. Loading new config {config_filename:?} in cwd {cwd:?}");
                match load_config(config_filename).await {
                    Ok(config) => router.set_config(Arc::new(config)),
                    Err(e) => error!(
                        "Failed to load config {config_filename:?}, staying with old config: {e}"
                    ),
                }
            }
            _ = cleanup.tick() => {
                router.cleanup();
            }
        }
    }
}

fn bind_udp_socket(addr: SocketAddr, dual_stack: bool) -> Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket =
        Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("creating UDP socket")?;
    if addr.is_ipv6() {
        socket
            .set_only_v6(!dual_stack)
            .context("setting UDP socket dual-stack mode")?;
    }
    socket
        .bind(&addr.into())
        .with_context(|| format!("binding UDP socket to {addr}"))?;
    socket
        .set_nonblocking(true)
        .context("setting UDP socket nonblocking")?;
    UdpSocket::from_std(socket.into()).context("converting UDP socket to tokio")
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    tracing_subscriber::fmt()
        .with_env_filter(&opt.verbose)
        .with_writer(std::io::stderr)
        .event_format(tracing_subscriber::fmt::format().with_ansi(false))
        .init();
    info!("HTTP/3 SNI Router {}", version::version_string());

    let sockets = ProxySockets::new(opt.listen)?;
    debug!("Listening on UDP {}", sockets.client_addr()?);

    privs::h3_drop(
        &opt.restrict_dirs
            .iter()
            .map(std::path::PathBuf::as_path)
            .collect::<Vec<_>>(),
    )?;

    resolver::start_hosts_reload()?;
    let config = load_config(&opt.config)
        .await
        .with_context(|| format!("Loading config {:?}", opt.config))?;
    mainloop(
        sockets,
        Router::new(Arc::new(config), Duration::from_millis(opt.idle_timeout_ms)),
        &opt.config,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const AEAD_TAG_LEN: usize = 16;

    #[tokio::test]
    async fn idle_and_channel_blocked_readers_do_not_hold_receive_buffers() -> Result<()> {
        let backend = UdpSocket::bind("127.0.0.1:0").await?;
        let pool = Arc::new(PacketPool::default());
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut tasks = Vec::new();
        let mut addresses = Vec::new();
        for id in 0..64 {
            let socket = Arc::new(connect_backend_socket(backend.local_addr()?).await?);
            addresses.push(socket.local_addr()?);
            tasks.push(spawn_backend_reader(id, socket, tx.clone(), pool.clone()));
        }
        tokio::task::yield_now().await;
        assert_eq!(
            pool.allocated(),
            0,
            "idle readers allocated receive buffers"
        );
        for addr in addresses {
            backend.send_to(b"reply", addr).await?;
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while rx.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        tokio::task::yield_now().await;
        assert_eq!(pool.allocated(), 1, "channel waiters held receive buffers");
        let datagram = rx.recv().await.unwrap();
        assert_eq!(&*datagram.packet, b"reply");
        for task in tasks {
            task.abort();
        }
        Ok(())
    }

    #[tokio::test]
    async fn pooled_backend_receive_preserves_large_datagrams() -> Result<()> {
        let backend = UdpSocket::bind("127.0.0.1:0").await?;
        let socket = Arc::new(connect_backend_socket(backend.local_addr()?).await?);
        let pool = Arc::new(PacketPool::default());
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let task = spawn_backend_reader(7, socket.clone(), tx, pool.clone());
        let payload = vec![0xab; 60_000];
        backend.send_to(&payload, socket.local_addr()?).await?;
        let datagram = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await?
            .unwrap();
        assert_eq!(datagram.conn_id, 7);
        assert_eq!(&*datagram.packet, payload);
        drop(datagram);
        backend.send_to(&payload, socket.local_addr()?).await?;
        let datagram = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await?
            .unwrap();
        assert_eq!(&*datagram.packet, payload);
        assert_eq!(
            pool.allocated(),
            1,
            "second datagram did not reuse its buffer"
        );
        task.abort();
        Ok(())
    }

    async fn make_config(s: &str) -> Result<Config> {
        let tmp_dir = tempfile::TempDir::new()?;
        let config_file = tmp_dir.path().join("config.cfg");
        std::fs::write(&config_file, s)?;
        load_config(config_file.to_str().unwrap()).await
    }

    fn hex_to_vec(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn push_u16_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(
            &u16::try_from(value.len())
                .expect("test vector length fits in u16")
                .to_be_bytes(),
        );
        out.extend_from_slice(value);
    }

    fn minimal_clienthello_sni(host: &str) -> Vec<u8> {
        let mut server_name_list = Vec::new();
        server_name_list.push(0);
        push_u16_len_prefixed(&mut server_name_list, host.as_bytes());

        let mut server_name_ext = Vec::new();
        push_u16_len_prefixed(&mut server_name_ext, &server_name_list);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        push_u16_len_prefixed(&mut extensions, &server_name_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        push_u16_len_prefixed(&mut body, &extensions);

        let mut hello = Vec::new();
        hello.push(1);
        let len = body.len();
        hello.extend_from_slice(&[
            u8::try_from((len >> 16) & 0xff).unwrap(),
            u8::try_from((len >> 8) & 0xff).unwrap(),
            u8::try_from(len & 0xff).unwrap(),
        ]);
        hello.extend_from_slice(&body);
        hello
    }

    fn encode_varint(value: u64) -> Vec<u8> {
        if value < 64 {
            vec![u8::try_from(value).unwrap()]
        } else if value < 16_384 {
            let value = u16::try_from(value).unwrap() | 0x4000;
            value.to_be_bytes().to_vec()
        } else if value < 1_073_741_824 {
            let value = u32::try_from(value).unwrap() | 0x8000_0000;
            value.to_be_bytes().to_vec()
        } else {
            let value = value | 0xc000_0000_0000_0000;
            value.to_be_bytes().to_vec()
        }
    }

    fn crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x06];
        frame.extend_from_slice(&encode_varint(offset));
        frame.extend_from_slice(&encode_varint(u64::try_from(data.len()).unwrap()));
        frame.extend_from_slice(data);
        frame
    }

    fn long_packet_with_cids(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(0xc0);
        packet.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        packet.push(u8::try_from(dcid.len()).unwrap());
        packet.extend_from_slice(dcid);
        packet.push(u8::try_from(scid.len()).unwrap());
        packet.extend_from_slice(scid);
        packet
    }

    fn protected_initial_packet(dcid: &[u8], scid: &[u8], payload: &[u8]) -> Vec<u8> {
        let key_bytes = initial_key_bytes(dcid).unwrap();
        let open = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &key_bytes.key).unwrap(),
        );
        let hp = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &key_bytes.hp).unwrap();
        let packet_number = 0u64;
        let packet_number_bytes = [0u8, 0, 0, 0];

        let mut ciphertext = payload.to_vec();
        let mut header = Vec::new();
        header.push(0xc3);
        header.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        header.push(u8::try_from(dcid.len()).unwrap());
        header.extend_from_slice(dcid);
        header.push(u8::try_from(scid.len()).unwrap());
        header.extend_from_slice(scid);
        header.push(0);
        let packet_len = packet_number_bytes.len() + ciphertext.len() + AEAD_TAG_LEN;
        header.extend_from_slice(&encode_varint(u64::try_from(packet_len).unwrap()));
        let packet_number_offset = header.len();
        header.extend_from_slice(&packet_number_bytes);

        open.seal_in_place_append_tag(
            packet_nonce(&key_bytes.iv, packet_number),
            aead::Aad::from(&header),
            &mut ciphertext,
        )
        .unwrap();

        let mut packet = header;
        packet.extend_from_slice(&ciphertext);
        let sample_offset = packet_number_offset + 4;
        let mask = hp
            .new_mask(&packet[sample_offset..sample_offset + aead::quic::AES_128.sample_len()])
            .unwrap();
        packet[0] ^= mask[0] & 0x0f;
        for i in 0..packet_number_bytes.len() {
            packet[packet_number_offset + i] ^= mask[i + 1];
        }
        packet
    }

    #[tokio::test]
    async fn h3_config_uses_proxy_addr_as_udp_backend() -> Result<()> {
        let config = make_config(
            r#"
rules: <
    regex: "www[.]example[.]com"
    backend: <
        proxy: <
            addr: "[::1]:8443"
        >
    >
>
default: <
    backend: <
        null: <>
    >
>
"#,
        )
        .await?;
        match &config.rules[0].backend {
            Backend::Udp { addr } => assert_eq!(addr.to_string(), "[::1]:8443"),
            other => panic!("unexpected backend {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn h3_config_rejects_tcp_only_pass_backend() {
        let config = make_config(
            r#"
default: <
    backend: <
        pass: <
            path: "x.sock"
        >
    >
>
"#,
        )
        .await;
        assert!(config.is_err(), "unexpected config: {config:?}");
    }

    #[tokio::test]
    async fn default_acl_controls_fallback_routes() -> Result<()> {
        for (peer, source) in [
            ("127.0.0.1:12345", "127.0.0.0/8"),
            ("[::ffff:127.0.0.1]:12345", "127.0.0.0/8"),
            ("[::1]:12345", "::1/128"),
        ] {
            for (default_action, rule_action, allowed) in [
                ("DROP", None, false),
                ("CONTINUE", None, false),
                ("UNSPECIFIED", None, false),
                ("ACCEPT", None, true),
                ("DROP", Some("ACCEPT"), true),
                ("ACCEPT", Some("DROP"), false),
            ] {
                let rules = rule_action.map_or_else(String::new, |action| {
                    format!("rules: < source: {source:?} action: {action} >")
                });
                let config = make_config(&format!(
                    "default: < acl: < default_action: {default_action} {rules} >
                     backend: < proxy: < addr: \"127.0.0.1:443\" > > >"
                ))
                .await?;
                let router = Router::new(Arc::new(config), Duration::from_secs(60));
                for sni in [None, Some("unmatched.example.com".to_string())] {
                    let route = router.route_for_sni(peer.parse()?, sni);
                    let forwarded = route.is_ok_and(|r| matches!(r.backend, Backend::Udp { .. }));
                    assert_eq!(
                        forwarded, allowed,
                        "peer={peer} default={default_action} rule={rule_action:?}"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn extracts_sni_from_tls_clienthello() -> Result<()> {
        let hello = minimal_clienthello_sni("www.example.com");
        assert_eq!(
            extract_tls_sni(&hello)?,
            Some("www.example.com".to_string())
        );
        Ok(())
    }

    #[test]
    fn shorter_crypto_retransmission_preserves_clienthello() -> Result<()> {
        let hello = minimal_clienthello_sni("www.example.com");
        let split = hello.len() / 2;
        let mut crypto = CryptoReassembly::default();
        crypto.insert(0, &hello[..split]);
        crypto.insert(0, &hello[..split / 2]);
        crypto.insert(u64::try_from(split)?, &hello[split..]);
        assert_eq!(crypto.clienthello()?, Some(hello.as_slice()));
        Ok(())
    }

    #[test]
    fn crypto_reassembly_handles_gaps_overlaps_and_fragment_order() -> Result<()> {
        let hello = minimal_clienthello_sni("www.example.com");
        let cuts = [0, 10, 30, hello.len()];
        for order in [[0, 1, 2], [2, 0, 1], [1, 2, 0], [2, 1, 0]] {
            let mut crypto = CryptoReassembly::default();
            for (step, part) in order.into_iter().enumerate() {
                crypto.insert(
                    u64::try_from(cuts[part])?,
                    &hello[cuts[part]..cuts[part + 1]],
                );
                if step < 2 {
                    assert!(crypto.clienthello()?.is_none());
                }
            }
            assert_eq!(crypto.clienthello()?, Some(hello.as_slice()));
            assert_eq!(
                crypto.clienthello()?.unwrap().as_ptr(),
                crypto.bytes.as_ptr()
            );
            assert!(crypto.fragments.is_empty());
        }

        let mut crypto = CryptoReassembly::default();
        crypto.insert(20, &hello[20..50]);
        crypto.insert(20, &hello[20..25]);
        crypto.insert(10, &hello[10..30]);
        crypto.insert(0, &hello[..15]);
        assert_eq!(crypto.bytes, hello[..50]);
        crypto.insert(45, &hello[45..]);
        crypto.insert(0, &hello[..10]);
        assert_eq!(crypto.clienthello()?, Some(hello.as_slice()));
        crypto.insert(u64::MAX, b"sparse fragment");
        assert_eq!(crypto.bytes.len(), hello.len());
        Ok(())
    }

    #[test]
    fn crypto_frames_borrow_the_decrypted_payload() -> Result<()> {
        let payload = crypto_frame(0, b"hello");
        let frames = read_crypto_frames(&payload)?;
        assert_eq!(frames[0].1, b"hello");
        assert_eq!(frames[0].1.as_ptr(), payload[3..].as_ptr());
        assert!(read_crypto_frames(&payload[..payload.len() - 1]).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn initial_and_established_packets_reach_backend_unchanged() -> Result<()> {
        let backend = UdpSocket::bind("127.0.0.1:0").await?;
        let config = make_config(&format!(
            "default: < backend: < proxy: < addr: \"{}\" > > >",
            backend.local_addr()?
        ))
        .await?;
        let mut router = Router::new(Arc::new(config), Duration::from_secs(60));
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let peer = "127.0.0.1:12345".parse()?;
        let dcid = b"server01";
        let hello = minimal_clienthello_sni("www.example.com");
        let initial = protected_initial_packet(dcid, b"client01", &crypto_frame(0, &hello));
        router.handle_datagram(peer, &initial, &tx).await?;
        let mut buf = vec![0; MAX_DATAGRAM_SIZE];
        let len = tokio::time::timeout(Duration::from_secs(2), backend.recv(&mut buf)).await??;
        assert_eq!(&buf[..len], initial);
        let mut packet = vec![0x40];
        packet.extend_from_slice(dcid);
        packet.extend_from_slice(b"encrypted application bytes");
        router.handle_datagram(peer, &packet, &tx).await?;
        let len = tokio::time::timeout(Duration::from_secs(2), backend.recv(&mut buf)).await??;
        assert_eq!(&buf[..len], packet);
        for (_, connection) in router.connections.drain() {
            connection.backend_task.abort();
        }
        Ok(())
    }

    #[test]
    fn quic_v1_initial_key_derivation_matches_rfc9001() -> Result<()> {
        let dcid = hex_to_vec("8394c8f03e515708");
        let key_bytes = initial_key_bytes(&dcid)?;
        assert_eq!(
            key_bytes.key.to_vec(),
            hex_to_vec("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(
            key_bytes.iv.to_vec(),
            hex_to_vec("fa044b2f42a3fd3b46fb255c")
        );
        assert_eq!(
            key_bytes.hp.to_vec(),
            hex_to_vec("9f50449e04a0e810283a1e9933adedd2")
        );
        Ok(())
    }

    #[test]
    fn decrypts_synthetic_quic_initial_crypto_frame() -> Result<()> {
        let dcid = hex_to_vec("8394c8f03e515708");
        let scid = hex_to_vec("0001020304050607");
        let hello = minimal_clienthello_sni("www.example.com");
        let payload = crypto_frame(0, &hello);
        let packet = protected_initial_packet(&dcid, &scid, &payload);

        let decrypted = decrypt_initial_packet(&packet)?;
        assert_eq!(decrypted.dcid, dcid);
        assert_eq!(decrypted.scid, scid);
        let frames = read_crypto_frames(&decrypted.payload)?;
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, 0);
        assert_eq!(frames[0].1, hello);
        Ok(())
    }

    #[tokio::test]
    async fn backend_reply_from_ipv4_on_dual_stack_socket_routes_to_client() -> Result<()> {
        let mut sockets = ProxySockets::new("[::]:0".parse()?)?;
        let backend_addr = SocketAddr::from(([127, 0, 0, 1], 443));
        let backend_socket = Arc::new(connect_backend_socket(backend_addr).await?);
        let client_socket = UdpSocket::bind("[::1]:0").await?;
        let client_addr = client_socket.local_addr()?;

        let config = Arc::new(
            make_config(
                r#"
default: <
    backend: <
        null: <>
    >
>
"#,
            )
            .await?,
        );
        let mut router = Router::new(config, Duration::from_secs(60));
        let conn_id = 7;
        let client_cid = b"client01".to_vec();
        router.cid_routes.insert(client_cid.clone(), conn_id);
        router.connections.insert(
            conn_id,
            Connection {
                backend_socket,
                backend_writer: None,
                backend_task: tokio::spawn(async {}),
                client_addr,
                cids: HashSet::from([client_cid.clone()]),
                created: Instant::now(),
                last_seen: Instant::now(),
                deadline: None,
                sni: Some("www.example.com".to_string()),
            },
        );

        let packet = long_packet_with_cids(&client_cid, b"server01");
        router
            .handle_backend_datagram(
                &mut sockets,
                BackendDatagram {
                    conn_id,
                    packet: router.packet_pool.copy_packet(&packet),
                },
            )
            .await?;

        let mut buf = [0u8; 2048];
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(1), client_socket.recv_from(&mut buf))
                .await??;
        assert_eq!(&buf[..n], packet);
        Ok(())
    }

    #[tokio::test]
    async fn backend_reply_with_unknown_dcid_routes_by_unique_backend() -> Result<()> {
        let mut sockets = ProxySockets::new("127.0.0.1:0".parse()?)?;
        let backend_addr = SocketAddr::from(([127, 0, 0, 1], 443));
        let backend_socket = Arc::new(connect_backend_socket(backend_addr).await?);
        let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let client_addr = client_socket.local_addr()?;

        let config = Arc::new(
            make_config(
                r#"
default: <
    backend: <
        null: <>
    >
>
"#,
            )
            .await?,
        );
        let mut router = Router::new(config, Duration::from_secs(60));
        let conn_id = 9;
        router.connections.insert(
            conn_id,
            Connection {
                backend_socket,
                backend_writer: None,
                backend_task: tokio::spawn(async {}),
                client_addr,
                cids: HashSet::new(),
                created: Instant::now(),
                last_seen: Instant::now(),
                deadline: None,
                sni: Some("www.example.com".to_string()),
            },
        );

        let server_cid = b"server01".to_vec();
        let packet = long_packet_with_cids(&[], &server_cid);
        router
            .handle_backend_datagram(
                &mut sockets,
                BackendDatagram {
                    conn_id,
                    packet: router.packet_pool.copy_packet(&packet),
                },
            )
            .await?;

        let mut buf = [0u8; 2048];
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(1), client_socket.recv_from(&mut buf))
                .await??;
        assert_eq!(&buf[..n], packet);
        assert_eq!(router.cid_routes.get(&server_cid), Some(&conn_id));
        Ok(())
    }

    #[tokio::test]
    async fn short_header_client_packet_with_no_cid_routes_by_client_addr() -> Result<()> {
        let backend_receiver = UdpSocket::bind("127.0.0.1:0").await?;
        let backend_addr = backend_receiver.local_addr()?;
        let backend_socket = Arc::new(connect_backend_socket(backend_addr).await?);
        let client_addr = SocketAddr::from(([127, 0, 0, 1], 49152));

        let config = Arc::new(
            make_config(
                r#"
default: <
    backend: <
        null: <>
    >
>
"#,
            )
            .await?,
        );
        let mut router = Router::new(config, Duration::from_secs(60));
        let conn_id = 11;
        router
            .client_routes
            .insert(normalize_socket_addr(client_addr), conn_id);
        router.connections.insert(
            conn_id,
            Connection {
                backend_socket,
                backend_writer: None,
                backend_task: tokio::spawn(async {}),
                client_addr,
                cids: HashSet::new(),
                created: Instant::now(),
                last_seen: Instant::now(),
                deadline: None,
                sni: Some("www.example.com".to_string()),
            },
        );

        let packet = vec![0x40, 0xde, 0xad, 0xbe, 0xef];
        let (backend_tx, _backend_rx) = tokio::sync::mpsc::channel::<BackendDatagram>(1);
        router
            .handle_datagram(client_addr, &packet, &backend_tx)
            .await?;

        let mut buf = [0u8; 2048];
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(1), backend_receiver.recv_from(&mut buf))
                .await??;
        assert_eq!(&buf[..n], packet);
        Ok(())
    }
    #[tokio::test]
    async fn cleanup_preserves_newer_connection_from_same_client() -> Result<()> {
        let backend = UdpSocket::bind("127.0.0.1:0").await?;
        let backend_addr = backend.local_addr()?;
        let config = make_config("default: < backend: < null: <> > >").await?;
        let mut router = Router::new(Arc::new(config), Duration::from_secs(60));
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let peer: SocketAddr = "127.0.0.1:40001".parse()?;
        for dcid in [b"old-cid1".to_vec(), b"new-cid2".to_vec()] {
            router
                .establish_and_flush(
                    PendingConnection::new(peer, dcid, Instant::now()),
                    Route {
                        backend: Backend::Udp { addr: backend_addr },
                        timeout: None,
                        sni: None,
                    },
                    &tx,
                )
                .await?;
        }
        let current_id = *router.client_routes.get(&peer).unwrap();
        let old_id = *router
            .connections
            .keys()
            .find(|id| **id != current_id)
            .unwrap();
        router.connections.get_mut(&old_id).unwrap().last_seen =
            Instant::now() - Duration::from_secs(61);
        router.cleanup();
        assert!(router.connections.contains_key(&current_id));
        assert_eq!(router.client_routes.get(&peer), Some(&current_id));
        Ok(())
    }

    #[tokio::test]
    async fn routing_regex_matches_entire_hostname() -> Result<()> {
        assert!(compile_full_match("example[.]com)|(?:evil").is_err());
        for (pattern, hostname, expected) in [
            ("example[.]com|example[.]com[.]au", "example.com.au", true),
            ("example[.]com|example[.]com[.]au", "example.com", true),
            (
                "example[.]com|example[.]com[.]au",
                "prefix.example.com",
                false,
            ),
            (
                "example[.]com|example[.]com[.]au",
                "example.com.au.evil",
                false,
            ),
            (".*?", "example.com", true),
            ("(?i)example[.]com", "EXAMPLE.COM", true),
            ("(?m)example[.]com", "example.com\nother", false),
            ("(?x)example [.] com # comment", "example.com", true),
            ("", "example.com", false),
            ("", "", true),
        ] {
            let rule = protos::Rule {
                regex: Some(pattern.into()),
                backend: Some(protos::Backend {
                    backend_type: Some(protos::backend::BackendType::Null(Default::default())),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let rule = load_rule(&rule, false).await?;
            assert_eq!(
                rule.re.is_match(hostname),
                expected,
                "pattern={pattern:?} hostname={hostname:?}"
            );
        }
        Ok(())
    }
}
