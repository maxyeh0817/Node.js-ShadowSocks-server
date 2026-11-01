# Shadowsocks AEAD Server

Zero-dependency Shadowsocks server with XHTTP transport, built on raw Node.js TCP sockets. Designed to run behind reverse proxies and CDN (e.g. Cloudflare).

## Features

- **Shadowsocks AEAD** (aes-256-gcm)
- **XHTTP/SplitHTTP transport** — pure HTTP GET/POST, works through any HTTP proxy/CDN
- No external dependencies — only Node.js built-in modules

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SERVER_PORT` | `20087` | Listening port |
| `SS_PASSWORD` | *(required)* | Shadowsocks password — server exits with code 1 if unset |
| `XHTTP_PATH` | `/xhttp` | XHTTP endpoint path prefix |
| `VERBOSE` | `true` | Enable SS/XHTTP debug logging |

## Usage

### Deploy

```bash
node index.js
# Listening on :20087  xhttp=/xhttp
```

Or with custom config:

```bash
SERVER_PORT=8080 SS_PASSWORD=mypassword XHTTP_PATH=/tunnel node index.js
```

The server exposes:

| Method | Path | Description |
|---|---|---|
| GET | `/` | Static HTML page |
| GET | `/xhttp/{uuid}` | XHTTP download stream |
| POST | `/xhttp/{uuid}/{seq}` | XHTTP upload packets |

### Reverse Proxy (Nginx)

```nginx
server {
    listen 443 ssl;
    server_name your.domain.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location /xhttp/ {
        proxy_pass http://127.0.0.1:20087;
        proxy_http_version 1.1;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;
        proxy_read_timeout 300s;
    }
}
```

---

## Client Configuration (v2rayNG)

### Transport: XHTTP

```
Protocol:       Shadowsocks
Server:         your.domain.com
Port:           443
Password:       <your SS_PASSWORD>
Encryption:     aes-256-gcm

Transport:      xhttp
XHTTP Mode:     auto
XHTTP Host:     your.domain.com
XHTTP Path:     /xhttp

TLS:            tls
SNI:            your.domain.com
Fingerprint:    chrome
ALPN:           h2,http/1.1
AllowInsecure:  false
```

### DNS Settings (Important)

When using VPN mode, configure DNS to avoid resolution failures:

**Option A: FakeDNS (Recommended)**

```
Remote DNS:     fakedns://198.18.0.0/15
Domestic DNS:   (leave empty)
```

FakeDNS returns fake IPs to apps, then maps them back to domain names when proxying. The server resolves domains on the remote side. This completely avoids DNS-over-UDP issues.

**Option B: DNS-over-HTTPS**

```
Remote DNS:     https://1.1.1.1/dns-query
Domestic DNS:   https://223.5.5.5/dns-query
```

Make sure routing rules send `1.1.1.1` through the proxy, not direct.

### v2rayNG Settings Summary

| Setting | Value |
|---|---|
| Mode | VPN |
| Domain Resolution | AsIs |

---

## Architecture

```
Client (v2rayNG)
  │
  │  TLS + HTTP/2
  ▼
Cloudflare / CDN
  │
  │  HTTP/1.1
  ▼
Reverse Proxy (nginx / hosting)
  │
  │  HTTP/1.1 (raw TCP)
  ▼
This Server (:20087)
  │
  ├─ GET  /xhttp/{uuid}      → chunked streaming (download)
  ├─ POST /xhttp/{uuid}/{seq} → upload packets
  │
  │  SS AEAD decrypt
  ▼
Target Server (e.g. google.com:443)
```

**XHTTP session lifecycle:**
1. Client sends `POST seq=0` with SS salt + encrypted target address
2. Server decrypts, connects to target
3. Client sends `GET` to open download stream (chunked response)
4. Subsequent `POST seq=1,2,3...` carry encrypted upstream data
5. Server sends encrypted downstream data via GET chunks
6. If GET stream is interrupted (CDN timeout), server buffers data and waits for GET reconnection

**Limits and backpressure:**
- Each POST body may be at most 1 MiB (`413` otherwise); keep the client's `scMaxEachPostBytes` at or below this (xray default: 1,000,000).
- POST connections are kept alive and may carry pipelined requests. A request's headers must complete within 15s; a POST body must arrive within 15s + 1s per 32 KiB of Content-Length. Idle keep-alive connections have no timeout (xray's upload pool reuses them at any time); when more than 256 are idle, the oldest is closed. Requests are parsed strictly: malformed or ambiguous headers (conflicting Content-Length, obs-fold, non-token names) get `400`, and `Transfer-Encoding` gets `411`; both close the connection.
- Received upload bytes (in-flight POST bodies plus out-of-order packets) share a 64 MiB process-wide budget; when it is full, new body data is answered with `503`.
- Out-of-order packets are queued per session up to 30 packets (xray's `scMaxBufferedPosts` default) or 32 MiB; beyond that the session is closed. If the oldest queued packet waits more than 20s for the gap (not counting time uploads are paused by backpressure), the session is closed. Only packets that advance the sequence (and downstream traffic) count as session activity.
- A session that never receives a GET download stream within 15s is closed (xray opens the GET while dialing, before its first POST). At the 200-session limit, the oldest session without a target connection is evicted to make room (first those without a GET stream); sessions with a target connection are never evicted.
- The GET stream is sent as `Content-Type: text/event-stream` (like xray's own server) so CDNs and reverse proxies stream it instead of buffering.
- When the target reads slower than the client uploads, the server stops reading the POST connection once more than 1 MiB is waiting for the target, and resumes when it drains. xray's uploader waits for each POST to be written before sending the next, so this throttles it. A client that opens a fresh connection per POST bypasses this; if more than 16 MiB ends up waiting for the target, the session is closed (large uploads to a slow target get disconnected).

## License

MIT
