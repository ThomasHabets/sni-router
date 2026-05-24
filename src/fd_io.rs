use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use anyhow::{Result, bail};
use libc::{EAGAIN, EINTR, MSG_DONTWAIT, MSG_NOSIGNAL, MSG_PEEK};
use tokio::io::unix::AsyncFd;

pub async fn peek_exact(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> Result<()> {
    loop {
        let mut guard = fd.readable().await?;
        let raw = fd.as_raw_fd();
        let r = unsafe {
            libc::recv(
                raw,
                buf.as_mut_ptr().cast(),
                buf.len(),
                MSG_PEEK | MSG_DONTWAIT,
            )
        };
        if r < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(EAGAIN) => {
                    guard.clear_ready();
                    continue;
                }
                Some(EINTR) => continue,
                _ => bail!("recv peek: {err}"),
            }
        }
        let n = r as usize;
        if n == 0 {
            bail!("EOF peek (wanted {})", buf.len());
        }
        if n < buf.len() {
            guard.clear_ready();
            continue;
        }
        return Ok(());
    }
}

pub async fn recv_exact(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let mut guard = fd.readable().await?;
        let raw = fd.as_raw_fd();
        let r = unsafe {
            libc::recv(
                raw,
                buf[filled..].as_mut_ptr().cast(),
                buf.len() - filled,
                MSG_DONTWAIT,
            )
        };
        if r < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(EAGAIN) => {
                    guard.clear_ready();
                    continue;
                }
                Some(EINTR) => continue,
                _ => bail!("recv: {err}"),
            }
        }
        if r == 0 {
            bail!("EOF (wanted {}, got {})", buf.len(), filled);
        }
        filled += r as usize;
    }
    Ok(())
}

pub async fn write_all(fd: &AsyncFd<OwnedFd>, buf: &[u8]) -> Result<()> {
    let mut sent = 0;
    while sent < buf.len() {
        let mut guard = fd.writable().await?;
        let raw = fd.as_raw_fd();
        let r = unsafe {
            libc::send(
                raw,
                buf[sent..].as_ptr().cast(),
                buf.len() - sent,
                MSG_NOSIGNAL | MSG_DONTWAIT,
            )
        };
        if r < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(EAGAIN) => {
                    guard.clear_ready();
                    continue;
                }
                Some(EINTR) => continue,
                _ => bail!("send: {err}"),
            }
        }
        sent += r as usize;
    }
    Ok(())
}
