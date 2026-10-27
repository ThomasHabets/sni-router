//! Shared Pushgateway export for both router binaries.

use std::collections::HashMap;

use anyhow::{Context, Result};

static HOSTNAME: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .map(|name| name.trim_end().to_owned())
                .unwrap_or_else(|_| "unknown".to_owned())
        })
});

pub(crate) fn push(registry: &prometheus::Registry, job: &str, url: &str) -> Result<()> {
    tracing::info!("Pushing metrics");
    prometheus::push_metrics(
        job,
        HashMap::from([("instance".to_owned(), (*HOSTNAME).clone())]),
        url,
        registry.gather(),
        None,
    )?;
    Ok(())
}

pub(crate) fn start(registry: prometheus::Registry, job: String, url: String) -> Result<()> {
    std::thread::Builder::new()
        .name("prometheus-pusher".to_owned())
        .spawn(move || {
            loop {
                if let Err(err) = push(&registry, &job, &url) {
                    eprintln!("failed to push prometheus metrics: {err}");
                }
                std::thread::sleep(std::time::Duration::from_mins(1));
            }
        })
        .context("spawn prometheus pusher thread")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::time::Duration;

    use prometheus::Encoder;

    use super::*;

    #[test]
    fn pushes_registry_with_job_and_instance_and_reports_http_errors() -> Result<()> {
        let registry = prometheus::Registry::new();
        let counter = prometheus::IntCounter::new("test_packets_total", "Packets")?;
        registry.register(Box::new(counter.clone()))?;
        counter.inc_by(7);
        let mut expected = Vec::new();
        prometheus::ProtobufEncoder::new().encode(&registry.gather(), &mut expected)?;

        for status in ["200 OK", "503 Service Unavailable"] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            let url = format!("http://{}", listener.local_addr()?);
            let server = std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(std::time::Instant::now() < deadline, "no metrics request");
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => panic!("accept: {e}"),
                    }
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                }
                let header = String::from_utf8(header).unwrap();
                let length: usize = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                let mut body = vec![0; length];
                socket.read_exact(&mut body).unwrap();
                write!(
                    socket,
                    "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
                (header, body)
            });
            let result = push(&registry, "h3-test", &url);
            let (header, body) = server.join().unwrap();
            assert!(header.starts_with("PUT /metrics/job/h3-test/instance/"));
            assert_eq!(body, expected);
            assert_eq!(result.is_ok(), status == "200 OK");
        }
        Ok(())
    }
}
