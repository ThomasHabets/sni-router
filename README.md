# SNI router

<https://github.com/ThomasHabets/sni-router>

A TLS frontend for routing TLS clients (like web clients) to different backends
depending on Server Name Indicator (SNI).

The connection to the backend can be proxied, with or without PROXY protocol,
and optionally with "frontend TLS".

The connection can also be handed off to the backend over a UNIX domain socket.
The benefit of that is that once the TLS handshake is over, sni-router is no
longer in the connection path, and can be restarted without interrupting
existing connections.

## Example config

```
rules: <
        regex: "disabled[.]example[.]com"
        backend: <
                # Just close the connection.
                null: <>
        >
>
rules: <
        regex: "(www[.]|)example[.]com"
        backend: <
                # Do the full TLS handshake, set up kTLS, and proxy to a
                # webserver (or any other type of server) that works 100% with
                # plaintext and no secret keys, using the PROXY protocol.
                #
                # TLS encryption over the wire is handled by the kernel.
                proxy: <
                        addr: "localhost:8080"
                        frontend_tls: <
                                cert_file: "fullchain.pem"
                                key_file: "privkey.pem"
                        >
                        proxy_header: true,
                >
        >
>
rules: <
        regex: "blog[.]example[.]com"
        backend: <
                # Pass to an nginx port that uses the PROXY protocol. The
                # backend will need to do TLS handshake and such.
                #
                # sni-router doesn't have the TLS key, the backend does.
                proxy: <
                        addr: "localhost:8080"
                        proxy_header: true
                >
        >
>
rules: <
        regex: "admin[.]example[.]com"

        # Only allow access from LAN.
        acl: <
                default_action: DROP
                rules: <
                        source: "192.168.0.0/16"
                        action: ACCEPT
                >
        >
        backend: <
                # Do the full TLS handshake, set up kTLS, and pass the file
                # descriptor to a webserver (or any other type of server) that
                # works 100% with plaintext and no secret keys.
                #
                # TLS encryption over the wire is handled by the kernel.
                pass: <
                        path: "pass.sock",
                        frontend_tls: <
                                cert_file: "fullchain.pem"
                                key_file: "privkey.pem"
                        >
                >
        >
>
default: <
        backend: <
                # For all other traffic, pass to an nginx port that uses the PROXY
                # protocol. Let that backend deal with TLS handshake and stuff.
                proxy: <
                        addr: "localhost:444"
                        proxy_header: true,
                >
        >
>
```

## TCP metrics

The TCP `sni-router` collects Prometheus metrics and can push them to a gateway
with `--prometheus URL`. `--prometheus-job` defaults to `sni-router`.

The `sni` counter records the literal client-provided hostname only after a
routing rule matches and its ACL accepts; unmatched and missing names use fixed
labels. Each observed matching hostname creates a metric series retained for
the lifetime of the process. A regex permitting unbounded distinct matching
SNIs therefore necessarily permits unbounded metric storage, even after those
connections close.

`frontend_handshakes` also records the actual TLS SNI on successful frontend
handshakes, including default frontend-TLS routes. Disabling metric export does
not stop collection or retention.

## DNS resolution

The default `hickory-resolver` Cargo feature uses a shared asynchronous DNS
resolver with caching and coalescing of identical in-flight queries. It reads
the system DNS configuration at startup and reloads `/etc/hosts` every minute.
If a hosts-file reload fails, the previous snapshot remains active and an error
is logged. With `--restrict-dirs`, include the paths needed to read
`/etc/resolv.conf` and `/etc/hosts`.

Build with `cargo build --no-default-features` to use Tokio's system resolver
instead. Numeric backend addresses bypass DNS in either build.

TCP backend names are resolved for each new connection. HTTP/3 backend names
are resolved when loading the configuration; send SIGHUP to refresh their
configured addresses. Existing connections retain their selected backend.

## Frontend TLS

Remaining TCP correctness issues and hardening work are tracked in
[TCP_REVIEW.md](TCP_REVIEW.md).

Set the top-level `handshake_timeout_ms` to limit connection setup, including
ClientHello routing, backend connection and backend TLS, frontend TLS completion
and kTLS setup, and Unix socket FD handoff. For example:

```protobuf
handshake_timeout_ms: 5000
```

A single deadline covers all these phases, including sorry backends. It stops
applying once connection setup completes; established traffic is not subject to
this deadline. Zero or omission disables it. TLS passed through to a backend is
not completed by the router and is outside this timeout. Global and per-rule
`max_lifetime_ms` limits also continue to apply and can expire first.

SNI Router can terminate Frontend TLS, meaning SNI router is the only process
that has access to the certificate keys. Backends then don't have to worry about
TLS at all.

Of course, that means that the connection between SNI Router and the backend is
not encrypted. If it's all on localhost, then it's fine.

Even when SNI Router is not in line with the connection, because it handed the
socket off over a UNIX domain socket, the backend doesn't have to deal with TLS.
This thanks to kTLS, having the kernel do the TLS leaving user space to work in
plain text.

If using kTLS, if the peer initiates TLS 1.3 Key Update, the connection will
fail with `EKEYEXPIRED`. Since the handed-to process doesn't have access to the
previous key material, it is unable to handle a key update. See [kernel
docs](https://kernel.org/doc/html/latest/networking/tls.html).

## Backend TLS and mTLS

`proxy.backend_tls` enables TLS to the backend. To authenticate with a client
certificate, configure a PEM certificate chain (leaf first) and its matching
PEM private key:

```text
backend: <
        proxy: <
                addr: "backend.example.com:443"
                backend_tls: <
                        cert_file: "/etc/sni-router/client-chain.pem"
                        key_file: "/etc/sni-router/client-key.pem"
                >
        >
>
```

Both fields must be supplied together. Omitting both preserves TLS without
client authentication. Missing, empty, malformed, or mismatched credentials
fail configuration loading; an invalid SIGHUP reload keeps the previous
configuration active. Paths are relative to the process working directory and
must be readable under `--restrict-dirs`.

Backend certificates are verified against the system trust store by default.
`insecure: true` disables backend certificate verification but still supplies
configured client credentials when the backend requests them.

## Unix domain socket handoff

On unix systems you can hand off a file descriptor from one process to another,
over a UNIX socket.

The two main benefits are:
1. SNI Router is no longer in the path of the request, improving performance.
2. SNI Router can be restarted without interrupting existing connections.
3. The backend has direct access to the underlying socket, and can therefore get
   the real client IP address.

SNI Router can also listen on the same Unix datagram handoff protocol:

```
sni-router --listen-unix-datagram pass.sock --config backend.conf
```

That lets one SNI Router use `pass: < path: "pass.sock" >` with another SNI
Router as the backend. The receiving router uses the passed TCP fd plus the
initial bytes from the datagram and then applies its normal SNI routing rules.

Because the pre-read data is handed off with the file descriptor, a client that
presents more than the max message size will fail to connect.

Frontend TLS handshake reads stop at record boundaries. After the handshake,
only complete TLS records already buffered in userspace are processed into
plaintext for handoff. Later application ciphertext stays on the socket for
kTLS, so queued application data does not enlarge the handoff datagram.

## HTTP/3 / QUIC routing

The `sni-router-h3` binary listens on UDP and routes QUIC v1 / HTTP/3 traffic.
It decrypts QUIC Initial packets using the public Initial secrets, extracts SNI
from the TLS ClientHello in CRYPTO frames, then forwards the original UDP
datagrams unchanged. After routing is established, packets are routed by learned
QUIC connection IDs where possible. For unknown or zero-length CIDs, peer
affinity forwards traffic only when exactly one live connection matches the
client IP address and UDP port. This includes Handshake and 0-RTT packets and
coalesced datagrams beginning with an Initial that verifies with that
connection's Initial keys. Backend replies use the per-connection backend UDP
socket that received them.

Fresh Initial packets still undergo ClientHello reassembly, SNI routing, and
ACL evaluation, even when the client address and port already have a route.
Multiple connections may share a client address and port, but ambiguous
unknown-CID packets are dropped until only one live connection remains.

An already registered CID keeps its owner. New handshake registrations that
claim another path's CID are dropped and counted with the `cid_collision` drop
reason. Conflicting aliases observed on established paths are ignored; repeated
registration by the same owner is allowed.

CID changes advertised in encrypted `NEW_CONNECTION_ID` frames work through
peer affinity while the client IP address and port remain stable. The router
does not learn those CIDs from the encrypted frames; client migration or NAT
rebinding to a different address or port requires the opt-in QUIC-LB mode
described below.

UDP forwarding uses nonblocking sends. Congested sockets have a bounded queue
of up to 32 datagrams and 128 KiB. Excess datagrams are dropped so backpressure
on one backend does not stall routing for other connections.

It uses the same asciiproto config format, but only `null` and `proxy` backends
are supported. For `sni-router-h3`, `proxy.addr` is interpreted as a UDP backend
address and TCP-only options such as `proxy_header`, `pass`, `frontend_tls`, and
`sorry` are rejected.

```
sni-router-h3 --listen [::]:443 --config h3.conf
```

```
rules: <
        regex: "(www[.]|)example[.]com"
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
```


### Resource limits

The HTTP/3 router applies these global limits by default. All values must be
positive integers and can be changed with command-line flags:

| Flag | Default | Limits |
| --- | --- | --- |
| `--max-paths` | 1024 | Retained backend paths, each with a UDP socket and reader task |
| `--max-pending-handshakes` | 1024 | Simultaneous ClientHello reassemblies |
| `--max-pending-bytes` | 16777216 (16 MiB) | Total buffered Initial datagram bytes across pending handshakes |
| `--max-cids-per-path` | 64 | Retained CIDs per backend path, including initial and learned IDs |

When a limit is reached, the router refuses new allocations without evicting
existing routes. A new handshake that would exceed a path's CID budget is
rejected before forwarding, including handshakes sharing a QUIC-LB path. Later
CID aliases beyond the budget are ignored; existing routes continue forwarding.
Path capacity is released by periodic expiry cleanup. Pending capacity is
released when a handshake completes, is discarded, or expires.

Each pending handshake is also limited to 32 datagrams, 128 KiB of buffered
datagrams, and 128 outstanding out-of-order CRYPTO fragments. Handshakes that
exceed these per-handshake bounds are discarded entirely. The global byte
budget measures datagram buffering; CRYPTO reassembly and metadata consume
additional memory bounded by the per-handshake limits.

Resource drops are counted by `quic_routing_dropped_datagrams_total` with reasons
`path_limit`, `pending_handshake_limit`, `pending_bytes_limit`,
`crypto_fragment_limit`, and `cid_limit`. `quic_cid_limit_total` also counts
attempts to add CID aliases beyond the budget, even when the packet itself is
forwarded. `quic_pending_initial_bytes` reports current datagram buffering.

### Prometheus metrics

Like the TCP binary, `sni-router-h3` can push metrics to a Prometheus
Pushgateway. Export is disabled unless `--prometheus` is supplied:

```sh
sni-router-h3 --listen '[::]:443' --config h3.conf \
    --prometheus http://localhost:9091 --prometheus-job sni-router-h3
```

Metrics are pushed immediately and then every minute from a separate thread.
Failures are logged and retried at the next interval. `--prometheus-job` defaults
to `sni-router-h3` (the TCP binary defaults to `sni-router`). Both use the hostname
as the `instance` grouping label. There is no HTTP scrape endpoint.

| Metric | Meaning |
| --- | --- |
| `quic_paths_total` | Backend UDP paths created, including QUIC-LB migration paths |
| `quic_active_paths` | Retained backend UDP paths, removed on idle/lifetime cleanup |
| `quic_pending_initials` | Initial packet reassemblies awaiting SNI routing |
| `quic_pending_initial_bytes` | Buffered Initial datagram bytes across pending handshakes |
| `quic_cid_limit_total` | CID registrations refused by the per-path budget |
| `sni{sni="..."}` | ClientHellos reaching SNI routing; unmatched names use `<unknown>`, absent/unparseable names use `<missing>`, excess labels use `<other>` |
| `quic_routing_latency_ms` | Histogram from the first buffered Initial to an SNI routing decision |
| `quic_received_datagrams_total{source="client\|backend"}` | Received UDP datagrams |
| `quic_received_bytes_total{source="client\|backend"}` | Received UDP payload bytes |
| `quic_routing_dropped_datagrams_total{reason="..."}` | Datagrams discarded by routing, including null/ACL rejection, invalid packets, missing/ambiguous peers, and pending timeouts |
| `quic_errors_total{source="..."}` | Client receive errors and client/backend datagram handling errors |

A path can carry multiple QUIC connections, and QUIC-LB routing can create paths
without a ClientHello. These metrics do not measure completed TLS handshakes or
HTTP requests. Routing drops exclude kernel/socket losses and bounded send queue
losses. SNI labels for matching rules contain the client-supplied hostname, with
at most 1024 distinct names retained for the lifetime of the process. Additional
names and names longer than 255 bytes are counted under `<other>`, without
changing SNI routing. The reserved `<unknown>` and `<missing>` labels remain
available independently of that limit.

### Opt-in QUIC-LB routing and migration

To route server CIDs that have never been visible in a handshake, configure
QUIC-LB decoders and their backend mappings. With no `quic_lb` entries, routing
behavior remains unchanged, including the restriction to the original client
address.

```text
quic_lb: <
        config_id: 0
        key_file: "/etc/sni-router/quic-lb.key"
        servers: < server_id: 123 addr: "[::1]:8443" >
>
rules: <
        regex: "(www[.]|)example[.]com"
        backend: < proxy: < addr: "[::1]:8443" > >
>
default: < backend: < null: <> > >
```

Start tarweb-h3 with `--quic-lb-key-file`, `--quic-lb-server-id 123`, and
`--quic-lb-config-id 0` using the same key and configuration ID. Key files contain
32 hexadecimal characters with optional surrounding whitespace; keep them
readable only by the relevant services. Key-file paths, like other configuration
paths, are relative to the process working directory. They must be accessible
under `--restrict-dirs` for reloads.

Generate a random 128-bit QUIC-LB key with OpenSSL:

```sh
(umask 077; openssl rand -hex 16 > quic-lb.key)
```

This creates a file containing 32 hexadecimal characters and a newline, with
read and write permissions for its owner only. Place it at the configured
`key_file` path (`/etc/sni-router/quic-lb.key` in the example), adjusting ownership
so the router can read it. Give tarweb-h3 a copy of the same key file and pass its
path to `--quic-lb-key-file`. Generate the key once for both services; generating
separate keys will prevent the router from decoding the backend's CIDs.

This implementation supports the 17-byte single-pass AES-128 encoding of
`draft-ietf-quic-load-balancers-22`, with four-byte unsigned backend IDs.
Configurations 0 through 6 may coexist. Decoding a mapped backend ID takes
precedence over learned CID and client-address routing. CIDs without a configured
mapping continue through the existing routing fallbacks.

Initial packets with unroutable CIDs still undergo SNI routing and ACL checks.
**A routable backend ID is sufficient authorization for forwarding**, including
from a new client address; SNI ACLs are not checked again. QUIC-LB encryption is
not client authentication: the backend authenticates packets and validates new
paths using QUIC.

Each client address/backend pair has its own upstream UDP socket, retained
across CID changes. Replies return to the client address associated with that
socket, so old and new paths can operate concurrently. Connections to the same
backend sharing a client address also share the path. Path queues remain bounded
as described above. Idle and global lifetime timers apply per path; initial SNI
rules also contribute their deadlines, with the earliest deadline winning for
shared paths. Migration creates a path with fresh global/idle timers and does
not preserve the original connection's SNI rule lifetime limit.

For rotation, install a new decoder with an unused configuration ID in the
router first, then enable it on servers. Keep old configurations and backend
mappings until their connections have drained. Backend IDs must remain stable
within an active configuration. Configurations and key files reload on SIGHUP;
invalid reloads leave the previous configuration active. Existing paths retain
their upstream sockets and deadlines. Router restart recovery is not guaranteed.
