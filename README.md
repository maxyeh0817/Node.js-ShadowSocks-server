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
| `SS_PASSWORD` | `test123456` | Shadowsocks password |
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

## License

MIT
