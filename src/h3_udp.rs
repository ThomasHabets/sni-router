use std::io;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use socket2::SockRef;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub(crate) const MAX_DATAGRAM_SIZE: usize = 65_535;
const MAX_CACHED_BUFFERS: usize = 32;
const MAX_QUEUED_DATAGRAMS: usize = 32;
const MAX_QUEUED_BYTES: usize = 128 * 1024;

#[derive(Default)]
pub(crate) struct PacketPool {
    buffers: Mutex<Vec<Vec<u8>>>,
    #[cfg(test)]
    allocated: AtomicUsize,
}

impl PacketPool {
    pub(crate) fn acquire(self: &Arc<Self>) -> Packet {
        let cached = self
            .buffers
            .lock()
            .expect("packet pool lock poisoned")
            .pop();
        let buffer = cached.unwrap_or_else(|| {
            #[cfg(test)]
            self.allocated.fetch_add(1, Ordering::Relaxed);
            vec![0; MAX_DATAGRAM_SIZE]
        });
        Packet {
            buffer,
            len: 0,
            pool: self.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn copy_packet(self: &Arc<Self>, bytes: &[u8]) -> Packet {
        let mut packet = self.acquire();
        packet.buffer[..bytes.len()].copy_from_slice(bytes);
        packet.set_len(bytes.len());
        packet
    }

    #[cfg(test)]
    pub(crate) fn allocated(&self) -> usize {
        self.allocated.load(Ordering::Relaxed)
    }
}

pub(crate) struct Packet {
    buffer: Vec<u8>,
    len: usize,
    pool: Arc<PacketPool>,
}

impl Packet {
    pub(crate) fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    pub(crate) fn set_len(&mut self, len: usize) {
        assert!(len <= self.buffer.len());
        self.len = len;
    }
}

impl Deref for Packet {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}

impl Drop for Packet {
    fn drop(&mut self) {
        let mut buffers = self.pool.buffers.lock().expect("packet pool lock poisoned");
        if buffers.len() < MAX_CACHED_BUFFERS {
            buffers.push(std::mem::take(&mut self.buffer));
        }
    }
}

struct QueuedDatagram {
    packet: Vec<u8>,
    destination: Option<SocketAddr>,
}

pub(crate) struct SendQueue {
    sender: mpsc::Sender<QueuedDatagram>,
    pending_bytes: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl SendQueue {
    fn new(socket: Arc<UdpSocket>) -> Self {
        let (sender, mut receiver) = mpsc::channel::<QueuedDatagram>(MAX_QUEUED_DATAGRAMS);
        let pending_bytes = Arc::new(AtomicUsize::new(0));
        let pending = pending_bytes.clone();
        let task = tokio::spawn(async move {
            while let Some(datagram) = receiver.recv().await {
                let result = match datagram.destination {
                    Some(addr) => socket.send_to(&datagram.packet, addr).await,
                    None => socket.send(&datagram.packet).await,
                };
                if let Err(e) = result {
                    tracing::warn!("sending queued UDP datagram: {e}");
                }
                // Include one byte of accounting for empty datagrams.
                pending.fetch_sub(datagram.packet.len() + 1, Ordering::Release);
            }
        });
        Self {
            sender,
            pending_bytes,
            task,
        }
    }

    fn enqueue(&self, packet: &[u8], destination: Option<SocketAddr>) -> Result<bool> {
        let permit = match self.sender.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(_)) => return Ok(false),
            Err(mpsc::error::TrySendError::Closed(_)) => anyhow::bail!("UDP writer stopped"),
        };
        let charge = packet.len() + 1;
        let previous = self.pending_bytes.fetch_add(charge, Ordering::AcqRel);
        if previous + charge > MAX_QUEUED_BYTES {
            self.pending_bytes.fetch_sub(charge, Ordering::Release);
            return Ok(false);
        }
        permit.send(QueuedDatagram {
            packet: packet.to_vec(),
            destination,
        });
        Ok(true)
    }
}

impl Drop for SendQueue {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Send immediately without allocating, or queue on backpressure without waiting.
///
/// The socket is nonblocking. Using SockRef here attempts the syscall even when
/// Tokio has not yet observed write readiness for a newly connected socket.
pub(crate) fn send_or_queue(
    socket: &Arc<UdpSocket>,
    queue: &mut Option<SendQueue>,
    packet: &[u8],
    destination: Option<SocketAddr>,
) -> Result<()> {
    if queue
        .as_ref()
        .is_none_or(|q| q.pending_bytes.load(Ordering::Acquire) == 0)
    {
        let socket_ref = SockRef::from(socket.as_ref());
        let sent = match destination {
            Some(addr) => socket_ref.send_to(packet, &addr.into()),
            None => socket_ref.send(packet),
        };
        match sent {
            Ok(len) => {
                ensure!(len == packet.len(), "partial UDP datagram send");
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e).context("sending UDP datagram"),
        }
    }
    let queue = queue.get_or_insert_with(|| SendQueue::new(socket.clone()));
    if !queue.enqueue(packet, destination)? {
        tracing::debug!("dropping UDP datagram: bounded send queue full");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn receive_buffers_are_reused_and_cache_is_bounded() {
        let pool = Arc::new(PacketPool::default());
        let packet = pool.copy_packet(&[1, 2, 3]);
        let pointer = packet.as_ptr();
        assert_eq!(&*packet, &[1, 2, 3]);
        drop(packet);
        let packet = pool.acquire();
        assert_eq!(packet.buffer.as_ptr(), pointer);
        assert_eq!(pool.allocated(), 1);
        drop(packet);
        let packets: Vec<_> = (0..100).map(|_| pool.acquire()).collect();
        drop(packets);
        assert_eq!(pool.buffers.lock().unwrap().len(), MAX_CACHED_BUFFERS);
    }

    fn paused_queue(capacity: usize) -> (SendQueue, mpsc::Receiver<QueuedDatagram>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (
            SendQueue {
                sender,
                pending_bytes: Arc::new(AtomicUsize::new(0)),
                task: tokio::spawn(std::future::pending()),
            },
            receiver,
        )
    }

    #[tokio::test]
    async fn send_queues_bound_both_datagram_count_and_bytes() -> Result<()> {
        let (queue, _receiver) = paused_queue(2);
        assert!(queue.enqueue(b"one", None)?);
        assert!(queue.enqueue(b"two", None)?);
        assert!(!queue.enqueue(b"three", None)?);
        let (queue, _receiver) = paused_queue(32);
        let packet = vec![0; MAX_DATAGRAM_SIZE];
        assert!(queue.enqueue(&packet, None)?);
        assert!(queue.enqueue(&packet, None)?);
        assert!(!queue.enqueue(b"more", None)?);
        Ok(())
    }

    #[tokio::test]
    async fn queued_datagrams_stay_ordered_and_other_sockets_can_send() -> Result<()> {
        let receiver = UdpSocket::bind("127.0.0.1:0").await?;
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        socket.connect(receiver.local_addr()?).await?;
        let mut queue = Some(SendQueue::new(socket.clone()));
        for byte in 0..3 {
            assert!(queue.as_ref().unwrap().enqueue(&[byte], None)?);
        }
        send_or_queue(&socket, &mut queue, &[3], None)?;
        let mut buf = [0; 16];
        for byte in 0..4 {
            let len =
                tokio::time::timeout(Duration::from_secs(2), receiver.recv(&mut buf)).await??;
            assert_eq!(&buf[..len], &[byte]);
        }

        let (blocked, _receiver) = paused_queue(1);
        assert!(blocked.enqueue(b"blocked", None)?);
        let mut blocked = Some(blocked);
        send_or_queue(&socket, &mut blocked, b"dropped", None)?;
        send_or_queue(&socket, &mut None, b"unrelated", None)?;
        let len = tokio::time::timeout(Duration::from_secs(2), receiver.recv(&mut buf)).await??;
        assert_eq!(&buf[..len], b"unrelated");
        Ok(())
    }
}
