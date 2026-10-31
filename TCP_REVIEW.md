# TCP router correctness and hardening backlog

Open correctness issues and hardening work for the TCP `sni-router` binary in
[src/main.rs](src/main.rs), including frontend TLS, backend TLS, and Unix socket
handoff.

## Confirmed issues

### High: post-handshake TLS control messages are not handled

Frontend TLS returns a raw `TcpStream` after installing kTLS keys. Backend TLS
calls `KtlsStream::into_raw()` and also returns a raw stream. The proxy copy
loops therefore have no TLS control-message handler. For FD handoff, the
receiving process does not receive the userspace TLS state needed for updates.

Reproduction: complete a TLS 1.3 frontend handshake, send KeyUpdate followed by
application data, and read through the raw kTLS socket. The read fails with
`EIO`. After the control message is consumed, further reads can encounter
`EKEYEXPIRED` until new receive keys are installed; see the
[kernel TLS documentation](https://kernel.org/doc/html/latest/networking/tls.html).

Fix direction: retain ownership of post-handshake TLS state and process control
records, including key updates and alerts. Keep a TLS-aware stream on backend
connections instead of immediately discarding its wrapper. The current ktls
6.0.2 wrapper does not itself implement KeyUpdate handling, so preserving that
wrapper alone is insufficient. Test both proxy directions and define how FD
handoff recipients can support the required TLS control state.

### High: TCP connection and preread state lacks practical bounds

`mainloop` spawns a task for every accepted connection without an admission
limit. Both configured timeouts are optional. `read_tls_clienthello` trusts the
24-bit handshake length and retains both original wire records and the
reassembled handshake. There is no practical preread byte or record-count cap.

Reproduction: a declared 256 KiB handshake split into one-byte TLS record
payloads retains 1.5 MiB of wire data plus the 256 KiB handshake before SNI
validation. The declared handshake length can be much larger.

Fix direction: bound accepted connection tasks with admission control, cap
ClientHello size, total preread bytes, and record count. Include slow clients,
fragmented records, and capacity recovery in regression tests. Apply
these limits to both TCP accepts and received FD handoffs.
