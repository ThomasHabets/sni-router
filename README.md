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

## Frontend TLS

SNI Router can terminate Frontend TLS, meaning SNI router is the only process
that has access to the certificate keys. Backends then don't have to worry about
TLS at all.

Of course, that means that the connection between SNI Router and the backend is
not encrypted. If it's all on localhost, then it's fine.

Even when SNI Router is not in line with the connection, because it handed the
socket off over a UNIX domain socket, the backend doesn't have to deal with TLS.
This thanks to kTLS, having the kernel do the TLS leaving user space to work in
plain text.

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

## HTTP/3 / QUIC routing

The `sni-router-h3` binary listens on UDP and routes QUIC v1 / HTTP/3 traffic.
It decrypts QUIC Initial packets using the public Initial secrets, extracts SNI
from the TLS ClientHello in CRYPTO frames, then forwards the original UDP
datagrams unchanged. After routing is established, packets are routed by learned
QUIC connection IDs where possible. If an endpoint uses zero-length connection
IDs, client packets fall back to the client UDP address and backend replies use
the per-connection backend UDP socket that received them.

Because post-handshake QUIC frames are encrypted, the router cannot learn
connection IDs advertised later with `NEW_CONNECTION_ID`. Backends should keep
using connection IDs visible during the Initial exchange for traffic that must
pass through this router.

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
