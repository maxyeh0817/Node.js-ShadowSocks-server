import net from "net";
import fs from "fs";
import path from "path";
import crypto from "crypto";

/* ─── Load .env ─── */

try {
  const envPath = path.join(process.cwd(), ".env");
  for (const line of fs.readFileSync(envPath, "utf-8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.substring(0, eq).trim();
    const val = trimmed.substring(eq + 1).trim();
    if (!(key in process.env)) process.env[key] = val;
  }
} catch {}

/* ─── Configuration ─── */

const PORT = parseInt(process.env.SERVER_PORT || "20087");
const PASSWORD = process.env.SS_PASSWORD || "test123456";
const KEY_LEN = 32;
const SALT_LEN = 32;
const TAG_LEN = 16;
const NONCE_LEN = 12;
const MAX_CHUNK = 0x3fff;

/* ─── XHTTP/SplitHTTP configuration ─── */

const XHTTP_PATH = process.env.XHTTP_PATH || "/xhttp";
const XHTTP_SESSION_TIMEOUT = 120_000;
const XHTTP_MAX_PENDING = 64;
const XHTTP_CLEANUP_INTERVAL = 30_000;
const XHTTP_MAX_BUFFER = 4 * 1024 * 1024;  // 4MB buffer limit per session
const VERBOSE = process.env.VERBOSE !== "false";

/* ─── Key derivation ─── */

function evpBytesToKey(pwd: string, len: number): Buffer {
  const parts: Buffer[] = [];
  let prev: Buffer | null = null;
  let n = 0;
  while (n < len) {
    const src: Buffer[] = prev ? [prev] : [];
    src.push(Buffer.from(pwd));
    prev = crypto.createHash("md5").update(Buffer.concat(src)).digest();
    parts.push(prev);
    n += prev.length;
  }
  return Buffer.concat(parts).subarray(0, len);
}

function hkdfSHA1(ikm: Buffer, salt: Buffer, info: Buffer, len: number): Buffer {
  const prk = crypto.createHmac("sha1", salt).update(ikm).digest();
  const out: Buffer[] = [];
  let t = Buffer.alloc(0);
  for (let i = 1, n = 0; n < len; i++) {
    t = crypto
      .createHmac("sha1", prk)
      .update(Buffer.concat([t, info, Buffer.from([i])]))
      .digest();
    out.push(t);
    n += t.length;
  }
  return Buffer.concat(out).subarray(0, len);
}

const MASTER_KEY = evpBytesToKey(PASSWORD, KEY_LEN);
const SS_INFO = Buffer.from("ss-subkey");

/* ─── AEAD helpers ─── */

function aencrypt(key: Buffer, nonce: Buffer, plain: Buffer): Buffer {
  const c = crypto.createCipheriv("aes-256-gcm", key, nonce);
  const enc = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([enc, c.getAuthTag()]);
}

function adecrypt(
  key: Buffer,
  nonce: Buffer,
  buf: Buffer,
  clen: number
): Buffer {
  const d = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  d.setAuthTag(buf.subarray(clen, clen + TAG_LEN));
  return Buffer.concat([d.update(buf.subarray(0, clen)), d.final()]);
}

/* ─── Nonce ─── */

class Nonce {
  private b = Buffer.alloc(NONCE_LEN);
  peek() {
    return Buffer.from(this.b);
  }
  next() {
    const r = Buffer.from(this.b);
    for (let i = 0; i < NONCE_LEN; i++) {
      this.b[i]++;
      if (this.b[i] !== 0) break;
    }
    return r;
  }
}

/* ─── SS AEAD codec ─── */

class Decryptor {
  private k: Buffer;
  private n = new Nonce();
  private buf = Buffer.alloc(0);

  constructor(master: Buffer, salt: Buffer) {
    this.k = hkdfSHA1(master, salt, SS_INFO, KEY_LEN);
  }

  feed(data: Buffer): Buffer[] {
    this.buf = Buffer.concat([this.buf, data]);
    const out: Buffer[] = [];
    while (true) {
      if (this.buf.length < 2 + TAG_LEN) break;
      const lb = adecrypt(
        this.k,
        this.n.peek(),
        this.buf.subarray(0, 2 + TAG_LEN),
        2
      );
      const plen = lb.readUInt16BE(0);
      if (plen > MAX_CHUNK) throw new Error("chunk too large");
      const need = 2 + TAG_LEN + plen + TAG_LEN;
      if (this.buf.length < need) break;
      this.n.next();
      out.push(
        adecrypt(
          this.k,
          this.n.next(),
          this.buf.subarray(2 + TAG_LEN, need),
          plen
        )
      );
      this.buf = this.buf.subarray(need);
    }
    return out;
  }
}

class Encryptor {
  readonly salt: Buffer;
  private k: Buffer;
  private n = new Nonce();

  constructor(master: Buffer) {
    this.salt = crypto.randomBytes(SALT_LEN);
    this.k = hkdfSHA1(master, this.salt, SS_INFO, KEY_LEN);
  }

  write(plain: Buffer): Buffer {
    const parts: Buffer[] = [];
    let off = 0;
    while (off < plain.length) {
      const end = off + Math.min(plain.length - off, MAX_CHUNK);
      const chunk = plain.subarray(off, end);
      off = end;
      const lb = Buffer.alloc(2);
      lb.writeUInt16BE(chunk.length);
      parts.push(aencrypt(this.k, this.n.next(), lb));
      parts.push(aencrypt(this.k, this.n.next(), chunk));
    }
    return Buffer.concat(parts);
  }
}

/* ─── XHTTP session state ─── */

interface XHTTPSession {
  id: string;
  dead: boolean;
  lastActivity: number;
  downSock: net.Socket | null;
  downReady: boolean;
  nextSeq: number;
  pendingPosts: Map<number, Buffer>;
  dec: Decryptor | null;
  enc: Encryptor | null;
  ssBuf: Buffer;
  remote: net.Socket | null;
  addrBuf: Buffer;
  addrDone: boolean;
  earlyEncryptedData: Buffer[];
  bufferSize: number;
}

const xhttpSessions = new Map<string, XHTTPSession>();

/* ─── Target address (SOCKS5 format) ─── */

function parseAddr(
  b: Buffer
): { host: string; port: number; len: number } | null {
  if (!b.length) return null;
  const t = b[0];
  if (t === 1) {
    if (b.length < 7) return null;
    return {
      host: `${b[1]}.${b[2]}.${b[3]}.${b[4]}`,
      port: b.readUInt16BE(5),
      len: 7,
    };
  }
  if (t === 3) {
    if (b.length < 2) return null;
    const dl = b[1];
    if (b.length < 2 + dl + 2) return null;
    return {
      host: b.subarray(2, 2 + dl).toString(),
      port: b.readUInt16BE(2 + dl),
      len: 2 + dl + 2,
    };
  }
  if (t === 4) {
    if (b.length < 19) return null;
    const p: string[] = [];
    for (let i = 0; i < 16; i += 2) p.push(b.readUInt16BE(1 + i).toString(16));
    return { host: p.join(":"), port: b.readUInt16BE(17), len: 19 };
  }
  return null;
}

/* ─── XHTTP utilities ─── */

function parseQueryParams(rawUrl: string): { path: string; params: Record<string, string> } {
  const qIdx = rawUrl.indexOf("?");
  if (qIdx === -1) return { path: rawUrl, params: {} };
  const path = rawUrl.substring(0, qIdx);
  const params: Record<string, string> = {};
  for (const pair of rawUrl.substring(qIdx + 1).split("&")) {
    const eq = pair.indexOf("=");
    if (eq > 0) params[decodeURIComponent(pair.substring(0, eq))] = decodeURIComponent(pair.substring(eq + 1));
  }
  return { path, params };
}

function isValidUUID(s: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
}

function writeChunk(sock: net.Socket, data: Buffer): boolean {
  if (!sock.writable) return false;
  sock.write(data.length.toString(16) + "\r\n");
  sock.write(data);
  sock.write("\r\n");
  return true;
}

/* ─── XHTTP/SplitHTTP transport ─── */

function createXHTTPSession(id: string): XHTTPSession {
  const s: XHTTPSession = {
    id,
    dead: false,
    lastActivity: Date.now(),
    downSock: null,
    downReady: false,
    nextSeq: 0,
    pendingPosts: new Map(),
    dec: null,
    enc: null,
    ssBuf: Buffer.alloc(0),
    remote: null,
    addrBuf: Buffer.alloc(0),
    addrDone: false,
    earlyEncryptedData: [],
    bufferSize: 0,
  };
  xhttpSessions.set(id, s);
  VERBOSE && console.log(`[xhttp] session created: ${id}`);
  return s;
}

function xhttpDie(s: XHTTPSession, reason?: string) {
  if (s.dead) return;
  s.dead = true;
  VERBOSE && console.log(`[xhttp] session closed (${reason || "unknown"}) id=${s.id}`);
  s.remote?.destroy();
  if (s.downSock?.writable) {
    try { s.downSock.write("0\r\n\r\n"); s.downSock.end(); } catch {}
  }
  s.pendingPosts.clear();
  xhttpSessions.delete(s.id);
}

function xhttpSendToClient(s: XHTTPSession, plain: Buffer) {
  if (s.dead) return;
  let encrypted: Buffer;
  if (!s.enc) {
    s.enc = new Encryptor(MASTER_KEY);
    encrypted = Buffer.concat([s.enc.salt, s.enc.write(plain)]);
    VERBOSE && console.log(`[xhttp] ← first reply ${plain.length}B plain, ${encrypted.length}B enc (inc salt) id=${s.id}`);
  } else {
    encrypted = s.enc.write(plain);
    VERBOSE && console.log(`[xhttp] ← reply ${plain.length}B plain, ${encrypted.length}B enc id=${s.id}`);
  }
  if (s.downSock && s.downReady) {
    writeChunk(s.downSock, encrypted);
  } else {
    s.bufferSize += encrypted.length;
    if (s.bufferSize > XHTTP_MAX_BUFFER) {
      VERBOSE && console.log(`[xhttp] buffer overflow ${s.bufferSize}B, killing session id=${s.id}`);
      xhttpDie(s, "buffer overflow");
      return;
    }
    VERBOSE && console.log(`[xhttp] ← buffered (GET not ready) ${encrypted.length}B total=${s.bufferSize}B id=${s.id}`);
    s.earlyEncryptedData.push(encrypted);
  }
}

function xhttpOnPlain(s: XHTTPSession, chunks: Buffer[]) {
  for (const c of chunks) {
    if (!s.addrDone) {
      s.addrBuf = Buffer.concat([s.addrBuf, c]);
      const a = parseAddr(s.addrBuf);
      if (!a) continue;
      s.addrDone = true;
      const rest = s.addrBuf.subarray(a.len);
      VERBOSE && console.log(`[ss] → ${a.host}:${a.port}`);
      s.remote = net.createConnection(a.port, a.host, () => {
        VERBOSE && console.log(`[xhttp] remote connected → ${a!.host}:${a!.port} id=${s.id}`);
        if (rest.length) {
          VERBOSE && console.log(`[xhttp] → remote initial ${rest.length}B id=${s.id}`);
          s.remote!.write(rest);
        }
      });
      s.remote.on("data", (d: Buffer) => xhttpSendToClient(s, d));
      s.remote.on("error", (e) => xhttpDie(s, `remote error: ${e.message}`));
      s.remote.on("close", () => xhttpDie(s, "remote close"));
    } else {
      VERBOSE && console.log(`[xhttp] → remote ${c.length}B id=${s.id}`);
      s.remote?.write(c);
    }
  }
}

function xhttpProcessUpload(s: XHTTPSession, seq: number, payload: Buffer) {
  if (s.dead) return;
  s.lastActivity = Date.now();

  if (seq < s.nextSeq) {
    VERBOSE && console.log(`[xhttp] duplicate seq=${seq} (expect ${s.nextSeq}), ignored id=${s.id}`);
    return;
  }
  if (seq > s.nextSeq) {
    if (s.pendingPosts.size >= XHTTP_MAX_PENDING) {
      xhttpDie(s, "too many pending posts");
      return;
    }
    VERBOSE && console.log(`[xhttp] out-of-order seq=${seq} (expect ${s.nextSeq}), queued (pending=${s.pendingPosts.size + 1}) id=${s.id}`);
    s.pendingPosts.set(seq, payload);
    return;
  }

  // seq === nextSeq: process this and drain consecutive pending
  const toProcess: Buffer[] = [payload];
  s.nextSeq++;
  let drained = 0;
  while (s.pendingPosts.has(s.nextSeq)) {
    toProcess.push(s.pendingPosts.get(s.nextSeq)!);
    s.pendingPosts.delete(s.nextSeq);
    s.nextSeq++;
    drained++;
  }
  if (drained > 0) VERBOSE && console.log(`[xhttp] drained ${drained} pending packets, nextSeq=${s.nextSeq} id=${s.id}`);

  for (const data of toProcess) {
    if (!s.dec) {
      s.ssBuf = Buffer.concat([s.ssBuf, data]);
      if (s.ssBuf.length < SALT_LEN) continue;
      VERBOSE && console.log("[ss] salt received (xhttp)");
      s.dec = new Decryptor(MASTER_KEY, s.ssBuf.subarray(0, SALT_LEN));
      const rest = s.ssBuf.subarray(SALT_LEN);
      s.ssBuf = Buffer.alloc(0);
      if (rest.length) {
        try { xhttpOnPlain(s, s.dec.feed(rest)); }
        catch (e: any) { VERBOSE && console.error("[ss] decrypt error:", e?.message); xhttpDie(s, "decrypt"); return; }
      }
    } else {
      try { xhttpOnPlain(s, s.dec.feed(data)); }
      catch (e: any) { VERBOSE && console.error("[ss] decrypt error:", e?.message); xhttpDie(s, "decrypt"); return; }
    }
  }
}

function xhttpDetachGet(s: XHTTPSession, reason: string) {
  if (s.dead) return;
  VERBOSE && console.log(`[xhttp] GET stream lost (${reason}), awaiting reconnect id=${s.id}`);
  s.downSock = null;
  s.downReady = false;
}

function handleXHTTPGet(sock: net.Socket, sessionId: string, clientIp: string) {
  let s = xhttpSessions.get(sessionId);
  if (!s) s = createXHTTPSession(sessionId);

  if (s.dead) {
    VERBOSE && console.log(`[xhttp] GET on dead session id=${sessionId}`);
    sock.end("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found");
    return;
  }

  // Support GET reconnection: detach old socket
  if (s.downSock) {
    VERBOSE && console.log(`[xhttp] GET reconnect (replacing old stream) id=${sessionId}`);
    try { s.downSock.destroy(); } catch {}
  }

  s.downSock = sock;
  sock.setKeepAlive(true, 10_000);
  sock.setNoDelay(true);
  const xpad = crypto.randomBytes(100 + Math.floor(Math.random() * 156)).toString("base64");
  sock.write(
    "HTTP/1.1 200 OK\r\n" +
    "Content-Type: application/octet-stream\r\n" +
    "Transfer-Encoding: chunked\r\n" +
    "X-Accel-Buffering: no\r\n" +
    "Cache-Control: no-store\r\n" +
    "Connection: keep-alive\r\n" +
    `X-Padding: ${xpad}\r\n` +
    "\r\n"
  );
  s.downReady = true;
  VERBOSE && console.log(`[xhttp] GET stream connected (${clientIp}) id=${sessionId}`);

  // flush any buffered data
  if (s.earlyEncryptedData.length > 0) {
    VERBOSE && console.log(`[xhttp] flushing ${s.earlyEncryptedData.length} buffered chunks (${s.bufferSize}B) id=${sessionId}`);
  }
  for (const buf of s.earlyEncryptedData) {
    writeChunk(sock, buf);
  }
  s.earlyEncryptedData = [];
  s.bufferSize = 0;

  // GET error/close is NOT fatal — allow reconnection
  sock.on("error", (err) => xhttpDetachGet(s!, `error: ${(err as any)?.message || err}`));
  sock.on("close", () => xhttpDetachGet(s!, "close"));
}

function handleXHTTPPost(
  sock: net.Socket,
  sessionId: string,
  seq: number,
  headers: Record<string, string>,
  body: Buffer,
  clientIp: string
) {
  let s = xhttpSessions.get(sessionId);
  if (!s) s = createXHTTPSession(sessionId);

  if (s.dead) {
    VERBOSE && console.log(`[xhttp] POST on dead session seq=${seq} id=${sessionId}`);
    sock.end("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found");
    return;
  }

  const contentLength = parseInt(headers["content-length"] || "0", 10);

  function finish(fullBody: Buffer) {
    VERBOSE && console.log(`[xhttp] POST seq=${seq} len=${fullBody.length} (${clientIp}) id=${sessionId}`);
    xhttpProcessUpload(s!, seq, fullBody);
    sock.end("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
  }

  if (body.length >= contentLength) {
    finish(body.subarray(0, contentLength));
  } else {
    // need to read more data
    let collected = Buffer.from(body);
    sock.on("data", (chunk: Buffer) => {
      collected = Buffer.concat([collected, chunk]);
      if (collected.length >= contentLength) {
        finish(collected.subarray(0, contentLength));
      }
    });
    sock.on("error", () => sock.destroy());
  }
}

/* ─── Raw TCP server (bypass Node.js HTTP module) ─── */

const HTML = fs.readFileSync(path.join(process.cwd(), "public", "index.html"), "utf-8");

const server = net.createServer((sock) => {
  let buf = Buffer.alloc(0);
  let handled = false;

  function onData(chunk: Buffer) {
    if (handled) return;
    buf = Buffer.concat([buf, chunk]);

    // wait for complete HTTP headers
    const idx = buf.indexOf("\r\n\r\n");
    if (idx === -1) {
      if (buf.length > 8192) { sock.destroy(); handled = true; }
      return;
    }

    handled = true;
    sock.removeListener("data", onData);

    const headerPart = buf.subarray(0, idx).toString();
    const body = buf.subarray(idx + 4); // data after headers
    const lines = headerPart.split("\r\n");
    const [method, rawUrl] = (lines[0] || "").split(" ");
    const { path: urlPath, params: qp } = parseQueryParams(rawUrl || "/");

    // parse headers
    const headers: Record<string, string> = {};
    for (let i = 1; i < lines.length; i++) {
      const sep = lines[i].indexOf(": ");
      if (sep > 0) headers[lines[i].substring(0, sep).toLowerCase()] = lines[i].substring(sep + 2);
    }

    // Route: GET / → HTML page
    if (method === "GET" && (urlPath === "/" || urlPath === "/index.html")) {
      const htmlBuf = Buffer.from(HTML, "utf-8");
      sock.end(
        `HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${htmlBuf.length}\r\nConnection: close\r\n\r\n` +
          HTML
      );
      return;
    }

    // Route: XHTTP — path format: /xhttp/{uuid} (GET) or /xhttp/{uuid}/{seq} (POST)
    const xhttpPrefix = XHTTP_PATH.endsWith("/") ? XHTTP_PATH : XHTTP_PATH + "/";
    const clientIp = headers["x-forwarded-for"] || sock.remoteAddress || "unknown";
    if (urlPath.startsWith(xhttpPrefix)) {
      const rest = urlPath.substring(xhttpPrefix.length);  // e.g. "uuid" or "uuid/0"
      const segments = rest.split("/").filter(Boolean);

      if (segments.length === 1 && isValidUUID(segments[0]) && method === "GET") {
        handleXHTTPGet(sock, segments[0], clientIp);
        return;
      }

      if (segments.length === 2 && isValidUUID(segments[0]) && method === "POST") {
        const seq = parseInt(segments[1], 10);
        if (isNaN(seq) || seq < 0) {
          sock.end("HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBad Request");
          return;
        }
        handleXHTTPPost(sock, segments[0], seq, headers, body, clientIp);
        return;
      }

      VERBOSE && console.log(`[xhttp] unmatched ${method} ${urlPath} (${clientIp})`);
    }

    // Everything else → 404
    console.log(`[http] 404 ${method} ${urlPath}`);
    sock.end("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found");
  }

  sock.on("data", onData);
  sock.on("error", () => sock.destroy());
});

server.listen(PORT, () => {
  console.log(`Listening on :${PORT}  xhttp=${XHTTP_PATH}`);
});

// XHTTP session cleanup
setInterval(() => {
  const now = Date.now();
  for (const [id, s] of xhttpSessions) {
    if (now - s.lastActivity > XHTTP_SESSION_TIMEOUT) {
      xhttpDie(s, "timeout");
    }
  }
}, XHTTP_CLEANUP_INTERVAL);
