use std::net::SocketAddr;

use anyhow::{Context, Result};

/// Resolve backend addresses, keeping numeric socket addresses on a fast path.
pub(crate) async fn lookup_host(addr: &str) -> Result<Vec<SocketAddr>> {
    if let Ok(addr) = addr.parse() {
        return Ok(vec![addr]);
    }
    #[cfg(feature = "hickory-resolver")]
    {
        let (host, port) = addr
            .rsplit_once(':')
            .context("backend address missing port")?;
        let port: u16 = port.parse().context("invalid backend port")?;
        let resolver = hickory::snapshot(hickory::shared()?)?;
        Ok(resolver
            .lookup_ip(host)
            .await?
            .iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
    #[cfg(not(feature = "hickory-resolver"))]
    {
        Ok(tokio::net::lookup_host(addr)
            .await
            .context("resolving system backend address")?
            .collect())
    }
}

/// Start the hosts-file refresh task once the process has entered its sandbox.
pub(crate) fn start_hosts_reload() -> Result<()> {
    #[cfg(feature = "hickory-resolver")]
    {
        tokio::spawn(hickory::reload_hosts_periodically(
            hickory::shared()?.clone(),
            "/etc/hosts".into(),
            std::time::Duration::from_secs(60),
        ));
    }
    Ok(())
}

#[cfg(feature = "hickory-resolver")]
mod hickory {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, OnceLock, RwLock};
    use std::time::Duration;

    use super::*;
    use hickory_resolver::{Hosts, TokioResolver};

    type SharedResolver = Arc<RwLock<Arc<TokioResolver>>>;
    static RESOLVER: OnceLock<SharedResolver> = OnceLock::new();

    pub(super) fn shared() -> Result<&'static SharedResolver> {
        if let Some(resolver) = RESOLVER.get() {
            return Ok(resolver);
        }
        let resolver = TokioResolver::builder_tokio()
            .context("reading system DNS configuration")?
            .build()
            .context("building DNS resolver")?;
        // Concurrent initialization may win; all callers use the same instance.
        let _ = RESOLVER.set(Arc::new(RwLock::new(Arc::new(resolver))));
        Ok(RESOLVER.get().expect("resolver initialized"))
    }

    pub(super) fn snapshot(resolver: &SharedResolver) -> Result<Arc<TokioResolver>> {
        Ok(resolver
            .read()
            .map_err(|_| anyhow::anyhow!("DNS resolver lock poisoned"))?
            .clone())
    }

    fn read_hosts(path: &Path) -> Result<Hosts> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("opening hosts file {}", path.display()))?;
        let mut hosts = Hosts::default();
        hosts.read_hosts_conf(file)?;
        Ok(hosts)
    }

    async fn reload_hosts(resolver: &SharedResolver, path: PathBuf) -> Result<()> {
        let hosts = tokio::task::spawn_blocking(move || read_hosts(&path)).await??;
        let mut current = resolver
            .write()
            .map_err(|_| anyhow::anyhow!("DNS resolver lock poisoned"))?;
        Arc::make_mut(&mut current).set_hosts(Arc::new(hosts));
        Ok(())
    }

    pub(super) async fn reload_hosts_periodically(
        resolver: SharedResolver,
        path: PathBuf,
        period: Duration,
    ) {
        let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(e) = reload_hosts(&resolver, path.clone()).await {
                tracing::warn!("reloading hosts file: {e:#}");
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use hickory_resolver::{config::ResolverConfig, net::runtime::TokioRuntimeProvider};

        fn test_resolver() -> Result<SharedResolver> {
            let config = ResolverConfig::from_parts(None, vec![], vec![]);
            let resolver =
                TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                    .build()?;
            Ok(Arc::new(RwLock::new(Arc::new(resolver))))
        }

        #[tokio::test]
        async fn periodic_reload_replaces_hosts() -> Result<()> {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("hosts");
            std::fs::write(&path, "127.0.0.1 backend.invalid old.invalid\n")?;
            let resolver = test_resolver()?;
            reload_hosts(&resolver, path.clone()).await?;
            assert_eq!(
                snapshot(&resolver)?
                    .lookup_ip("backend.invalid.")
                    .await?
                    .iter()
                    .next(),
                Some("127.0.0.1".parse()?)
            );

            std::fs::write(&path, "127.0.0.2 backend.invalid new.invalid\n")?;
            let task = tokio::spawn(reload_hosts_periodically(
                resolver.clone(),
                path,
                Duration::from_millis(10),
            ));
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let result = snapshot(&resolver)?.lookup_ip("backend.invalid.").await?;
                    if result.iter().next() == Some("127.0.0.2".parse()?) {
                        break Ok::<_, anyhow::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await??;
            task.abort();
            assert!(
                snapshot(&resolver)?
                    .lookup_ip("old.invalid.")
                    .await
                    .is_err()
            );
            assert!(snapshot(&resolver)?.lookup_ip("new.invalid.").await.is_ok());
            Ok(())
        }

        #[tokio::test]
        async fn failed_reload_preserves_hosts() -> Result<()> {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("hosts");
            std::fs::write(&path, "127.0.0.3 backend.invalid\n")?;
            let resolver = test_resolver()?;
            reload_hosts(&resolver, path.clone()).await?;
            std::fs::remove_file(&path)?;
            assert!(reload_hosts(&resolver, path).await.is_err());
            assert_eq!(
                snapshot(&resolver)?
                    .lookup_ip("backend.invalid.")
                    .await?
                    .iter()
                    .next(),
                Some("127.0.0.3".parse()?)
            );
            Ok(())
        }

        #[tokio::test]
        async fn shared_queries_and_dns_cache_survive_hosts_reload() -> Result<()> {
            use std::sync::atomic::{AtomicUsize, Ordering};

            use hickory_resolver::{
                config::{LookupIpStrategy, NameServerConfig},
                proto::{
                    op::{Message, MessageType},
                    rr::{RData, Record, rdata::A},
                },
            };

            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            let addr = socket.local_addr()?;
            let requests = Arc::new(AtomicUsize::new(0));
            let counter = requests.clone();
            let server = tokio::spawn(async move {
                let mut buf = [0; 4096];
                loop {
                    let (len, peer) = socket.recv_from(&mut buf).await?;
                    let mut message = Message::from_vec(&buf[..len])?;
                    counter.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    message.metadata.message_type = MessageType::Response;
                    message.metadata.recursion_available = true;
                    message.add_answer(Record::from_rdata(
                        message.queries[0].name().clone(),
                        60,
                        RData::A(A("127.0.0.4".parse()?)),
                    ));
                    socket.send_to(&message.to_vec()?, peer).await?;
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            });
            let mut nameserver = NameServerConfig::udp(addr.ip());
            nameserver.connections[0].port = addr.port();
            let mut builder = TokioResolver::builder_with_config(
                ResolverConfig::from_name_servers(vec![nameserver]),
                TokioRuntimeProvider::default(),
            );
            builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4Only;
            let resolver = Arc::new(RwLock::new(Arc::new(builder.build()?)));
            let first = snapshot(&resolver)?;
            let second = snapshot(&resolver)?;
            let (a, b) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(
                    first.lookup_ip("backend.example."),
                    second.lookup_ip("backend.example.")
                )
            })
            .await?;
            assert_eq!(a?.iter().next(), b?.iter().next());
            assert_eq!(requests.load(Ordering::Relaxed), 1);

            let dir = tempfile::tempdir()?;
            let path = dir.path().join("hosts");
            std::fs::write(&path, "127.0.0.5 backend.example\n")?;
            reload_hosts(&resolver, path.clone()).await?;
            assert_eq!(
                snapshot(&resolver)?
                    .lookup_ip("backend.example.")
                    .await?
                    .iter()
                    .next(),
                Some("127.0.0.5".parse()?)
            );
            std::fs::write(&path, "")?;
            reload_hosts(&resolver, path).await?;
            assert_eq!(
                snapshot(&resolver)?
                    .lookup_ip("backend.example.")
                    .await?
                    .iter()
                    .next(),
                Some("127.0.0.4".parse()?)
            );
            assert_eq!(requests.load(Ordering::Relaxed), 1);
            server.abort();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_numeric_addresses_and_system_localhost() -> Result<()> {
        for addr in ["127.0.0.1:443", "[::1]:443"] {
            assert_eq!(lookup_host(addr).await?, vec![addr.parse::<SocketAddr>()?]);
        }
        let localhost = lookup_host("localhost:8443").await?;
        assert!(!localhost.is_empty());
        assert!(
            localhost
                .iter()
                .all(|addr| addr.ip().is_loopback() && addr.port() == 8443)
        );
        assert!(lookup_host("localhost:invalid").await.is_err());
        Ok(())
    }
}
