import net from "net";
import fs from "fs";
import path from "path";
import crypto from "crypto";

/* ─── Configuration ─── */

const PORT = parseInt(process.env.SERVER_PORT || "20087");
const PASSWORD = process.env.SS_PASSWORD || "test123456";
const KEY_LEN = 32;
const SALT_LEN = 32;
const TAG_LEN = 16;
const NONCE_LEN = 12;
const MAX_CHUNK = 0x3fff;
const WS_GUID = "258EAFA5-E914-47DA-95CA-5AB9DCBE11D5";

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

/* ─── WebSocket ─── */

function wsAccept(key: string): string {
  return crypto
    .createHash("sha1")
    .update(key.trim() + WS_GUID)
    .digest("base64");
}

function wsRead(
  buf: Buffer
): { op: number; data: Buffer; len: number } | null {
  if (buf.length < 2) return null;
  const op = buf[0] & 0x0f;
  const masked = !!(buf[1] & 0x80);
  let plen = buf[1] & 0x7f;
  let off = 2;
  if (plen === 126) {
    if (buf.length < 4) return null;
    plen = buf.readUInt16BE(2);
    off = 4;
  } else if (plen === 127) {
    if (buf.length < 10) return null;
    plen = Number(buf.readBigUInt64BE(2));
    off = 10;
  }
  const mlen = masked ? 4 : 0;
  if (buf.length < off + mlen + plen) return null;
  let data: Buffer;
  if (masked) {
    const mask = buf.subarray(off, off + 4);
    off += 4;
    data = Buffer.alloc(plen);
    for (let i = 0; i < plen; i++) data[i] = buf[off + i] ^ mask[i & 3];
  } else {
    data = Buffer.from(buf.subarray(off, off + plen));
  }
  return { op, data, len: off + plen };
}

function wsWrite(op: number, data: Buffer): Buffer {
  let hdr: Buffer;
  if (data.length < 126) {
    hdr = Buffer.from([0x80 | op, data.length]);
  } else if (data.length < 0x10000) {
    hdr = Buffer.alloc(4);
    hdr[0] = 0x80 | op;
    hdr[1] = 126;
    hdr.writeUInt16BE(data.length, 2);
  } else {
    hdr = Buffer.alloc(10);
    hdr[0] = 0x80 | op;
    hdr[1] = 127;
    hdr.writeBigUInt64BE(BigInt(data.length), 2);
  }
  return Buffer.concat([hdr, data]);
}

/* ─── SS session over WebSocket ─── */

function ssSession(sock: net.Socket, remaining: Buffer) {
  let wsBuf = remaining.length ? Buffer.from(remaining) : Buffer.alloc(0);
  let ssBuf = Buffer.alloc(0);
  let dec: Decryptor | null = null;
  let enc: Encryptor | null = null;
  let remote: net.Socket | null = null;
  let addrBuf = Buffer.alloc(0);
  let addrDone = false;
  let dead = false;

  function die() {
    if (dead) return;
    dead = true;
    remote?.destroy();
    try {
      if (sock.writable) sock.end(wsWrite(0x08, Buffer.alloc(0)));
    } catch {}
  }

  function toClient(plain: Buffer) {
    if (dead || !sock.writable) return;
    if (!enc) {
      enc = new Encryptor(MASTER_KEY);
      sock.write(
        wsWrite(0x02, Buffer.concat([enc.salt, enc.write(plain)]))
      );
    } else {
      sock.write(wsWrite(0x02, enc.write(plain)));
    }
  }

  function onPlain(chunks: Buffer[]) {
    for (const c of chunks) {
      if (!addrDone) {
        addrBuf = Buffer.concat([addrBuf, c]);
        const a = parseAddr(addrBuf);
        if (!a) continue;
        addrDone = true;
        const rest = addrBuf.subarray(a.len);
        console.log(`[ss] → ${a.host}:${a.port}`);
        remote = net.createConnection(a.port, a.host, () => {
          if (rest.length) remote!.write(rest);
        });
        remote.on("data", (d: Buffer) => toClient(d));
        remote.on("error", die);
        remote.on("close", die);
      } else {
        remote?.write(c);
      }
    }
  }

  function tick() {
    while (true) {
      const f = wsRead(wsBuf);
      if (!f) break;
      wsBuf = wsBuf.subarray(f.len);

      if (f.op === 0x08) { die(); return; }
      if (f.op === 0x09) { sock.write(wsWrite(0x0a, f.data)); continue; }
      if (f.op === 0x02 || f.op === 0x00) {
        console.log(`[ss] frame len=${f.data.length}`);
        if (!dec) {
          ssBuf = Buffer.concat([ssBuf, f.data]);
          if (ssBuf.length < SALT_LEN) continue;
          console.log("[ss] salt received");
          dec = new Decryptor(MASTER_KEY, ssBuf.subarray(0, SALT_LEN));
          const rest = ssBuf.subarray(SALT_LEN);
          ssBuf = Buffer.alloc(0);
          if (rest.length) {
            try {
              onPlain(dec.feed(rest));
            } catch (e: any) {
              console.error("[ss] decrypt error:", e?.message);
              die();
              return;
            }
          }
        } else {
          try {
            onPlain(dec.feed(f.data));
          } catch (e: any) {
            console.error("[ss] decrypt error:", e?.message);
            die();
            return;
          }
        }
      }
    }
  }

  sock.on("data", (d: Buffer) => {
    if (!dead) {
      console.log(`[ws] data: ${d.length}B`);
      wsBuf = Buffer.concat([wsBuf, d]);
      tick();
    }
  });
  sock.on("error", () => die());
  sock.on("close", () => die());

  if (wsBuf.length) tick();
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
    const [method, url] = (lines[0] || "").split(" ");

    // parse headers
    const headers: Record<string, string> = {};
    for (let i = 1; i < lines.length; i++) {
      const sep = lines[i].indexOf(": ");
      if (sep > 0) headers[lines[i].substring(0, sep).toLowerCase()] = lines[i].substring(sep + 2);
    }

    // Route: GET / → HTML page
    if (method === "GET" && (url === "/" || url === "/index.html")) {
      const htmlBuf = Buffer.from(HTML, "utf-8");
      sock.end(
        `HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${htmlBuf.length}\r\nConnection: close\r\n\r\n` +
          HTML
      );
      return;
    }

    // Route: WebSocket upgrade on /ws
    if (
      method === "GET" &&
      url === "/ws" &&
      headers["upgrade"]?.toLowerCase() === "websocket"
    ) {
      const wsKey = headers["sec-websocket-key"];
      if (!wsKey) { sock.destroy(); return; }

      sock.write(
        "HTTP/1.1 101 Switching Protocols\r\n" +
          "Upgrade: websocket\r\n" +
          "Connection: Upgrade\r\n" +
          `Sec-WebSocket-Accept: ${wsAccept(wsKey)}\r\n` +
          "\r\n"
      );
      console.log(`[ws] handshake complete (${headers["x-forwarded-for"] || sock.remoteAddress})`);
      ssSession(sock, body);
      return;
    }

    // Everything else → 404
    sock.end("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found");
  }

  sock.on("data", onData);
  sock.on("error", () => sock.destroy());
});

server.listen(PORT, () => {
  console.log(`Listening on :${PORT}`);
});
