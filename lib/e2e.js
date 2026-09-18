// End-to-end encrypted sharing for the internet link.
//
// The visitor's browser (service worker) encrypts every request with a key made from
//   * the secret in the link's #fragment - browsers never send that part over the network, and
//   * the PIN, which is only ever typed on the visitor's device.
// Cloudflare therefore relays nothing but scrambled bytes: no URLs, headers, cookies or content.
// Your app is NEVER served in plain text - an unencrypted request only ever gets the PIN page.
const fs = require('fs');
const http = require('http');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { WebSocketServer, WebSocket } = require('ws');

const PUBLIC = path.join(__dirname, '..', 'public');
const readPublic = (file) => fs.readFileSync(path.join(PUBLIC, file), 'utf8');

const COMMON_JS = readPublic('e2e-common.js');
const PAGE_JS = `${COMMON_JS}\n${readPublic('e2e-page.js')}`;
const SW_JS = `${COMMON_JS}\nvar PAGE_JS = ${JSON.stringify(PAGE_JS)};\n${readPublic('e2e-sw.js')}`;
const BOOT_HTML = readPublic('e2e-boot.html');
const BOOT_JS = `${COMMON_JS}\n${readPublic('e2e-boot.js')}`.replace(/<\/script/gi, '<\\/script');

const ITERATIONS = 150000;
const MAX_FRAME = 4 * 1024 * 1024;
const CHUNK = 256 * 1024;
const SESSION_IDLE_MS = 12 * 3600 * 1000;
const REPLAY_WINDOW_MS = 10 * 60 * 1000;
const KEEPALIVE_MS = 25000;

// Headers we never forward from the visitor to your app
const DROP_HEADERS = new Set(['host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'te',
  'trailer', 'upgrade', 'content-length', 'accept-encoding', 'cookie', 'origin', 'referer', 'user-agent']);
const NULL_BODY = new Set([204, 205, 304]);
const COMPRESSIBLE = /^(text\/(?!event-stream)|application\/(javascript|x-javascript|json|xml|wasm|manifest\+json)|image\/svg)/i;

const b64 = (buf) => Buffer.from(buf).toString('base64url');
const unb64 = (str) => Buffer.from(String(str || ''), 'base64url');
const label = (name) => Buffer.from(`share-e2e/1 ${name}`);
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(Math.floor(n))); return b; };

function hmac(key, ...parts) {
  const h = crypto.createHmac('sha256', key);
  for (const part of parts) h.update(part);
  return h.digest();
}

function seal(key, flags, data, aad) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(Buffer.from([flags])), cipher.update(data), cipher.final(), cipher.getAuthTag()]);
  return Buffer.concat([u32(12 + body.length), iv, body]);
}

function unseal(key, frame, aad) {
  const iv = frame.subarray(0, 12);
  const tag = frame.subarray(frame.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(frame.subarray(12, frame.length - 16)), decipher.final()]);
  return { flags: plain[0], data: plain.subarray(1) };
}

async function* readFrames(stream) {
  let buffer = Buffer.alloc(0);
  for await (const chunk of stream) {
    buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk;
    while (buffer.length >= 4) {
      const len = buffer.readUInt32BE(0);
      if (len < 29 || len > MAX_FRAME) throw new Error('bad frame');
      if (buffer.length < 4 + len) break;
      yield buffer.subarray(4, 4 + len);
      buffer = buffer.subarray(4 + len);
    }
  }
  if (buffer.length) throw new Error('truncated');
}

class Limiter {
  constructor(max, windowMs = REPLAY_WINDOW_MS) { this.max = max; this.windowMs = windowMs; this.hits = new Map(); }
  recent(id) {
    const now = Date.now();
    const list = (this.hits.get(id) || []).filter((t) => now - t < this.windowMs);
    if (list.length) this.hits.set(id, list); else this.hits.delete(id);
    return list;
  }
  blocked(id) { return this.recent(id).length >= this.max; }
  add(id) { const list = this.recent(id); list.push(Date.now()); this.hits.set(id, list); }
}

class E2EShare {
  constructor({ target, pin, onUnlock = () => {}, onLockout = () => {} }) {
    this.target = target;
    this.onUnlock = onUnlock;
    this.onLockout = onLockout;
    this.secret = crypto.randomBytes(32);
    this.salt = crypto.randomBytes(16);
    this.sessions = new Map();
    this.pinFails = new Limiter(5);
    this.pinFailsGlobal = new Limiter(20);
    this.agent = new http.Agent({ keepAlive: true, maxSockets: 256 });
    this.wss = new WebSocketServer({ noServer: true, perMessageDeflate: false, maxPayload: 256 * 1024 * 1024 });

    const host = target.host.includes(':') ? `[${target.host}]` : target.host;
    this.targetOrigin = `http://${host}:${target.port}`;
    this.hostHeader = target.host === '::1' ? `localhost:${target.port}` : `${host}:${target.port}`;
    this.setPin(pin);

    this.pruneTimer = setInterval(() => this.prune(), 60000);
    this.pruneTimer.unref();
  }

  get linkFragment() { return `k=${b64(this.secret)}`; }

  setPin(pin) {
    this.pin = String(pin);
    this.key = crypto.pbkdf2Sync(Buffer.concat([this.secret, Buffer.from(this.pin, 'utf8')]), this.salt, ITERATIONS, 32, 'sha256');
    this.kickAll();
  }

  kickAll() {
    for (const session of this.sessions.values()) this.endSession(session);
    this.sessions.clear();
  }

  endSession(session) {
    for (const socket of session.sockets) { try { socket.close(4401, 'locked'); } catch {} }
    for (const res of session.streams) { try { res.destroy(); } catch {} }
  }

  activeDevices(withinMs = 5 * 60 * 1000) {
    const now = Date.now();
    return [...this.sessions.values()].filter((s) => now - s.lastSeen < withinMs).length;
  }

  prune() {
    const now = Date.now();
    for (const [sid, session] of this.sessions) {
      if (now - session.lastSeen > SESSION_IDLE_MS) {
        this.endSession(session);
        this.sessions.delete(sid);
        continue;
      }
      for (const [id, seen] of session.seen) if (now - seen > REPLAY_WINDOW_MS) session.seen.delete(id);
    }
  }

  clientIp(req) {
    return String(req.headers['cf-connecting-ip'] || req.socket.remoteAddress || '').replace(/^::ffff:/, '');
  }

  /* ---------------- server ---------------- */

  createServer() {
    const server = http.createServer((req, res) => {
      this.onRequest(req, res).catch(() => {
        if (!res.headersSent) res.writeHead(400);
        res.end();
      });
    });
    server.on('upgrade', (req, socket, head) => this.onUpgrade(req, socket, head));
    server.headersTimeout = 60000;
    server.requestTimeout = 0;
    server.keepAliveTimeout = 65000;
    this.server = server;
    return server;
  }

  listen(host, port) {
    const server = this.server || this.createServer();
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => {
        server.removeListener('error', reject);
        server.on('error', () => {});
        resolve(server.address().port);
      });
    });
  }

  close() {
    clearInterval(this.pruneTimer);
    this.kickAll();
    this.agent.destroy();
    if (this.server) this.server.close();
  }

  async onRequest(req, res) {
    if (!req.url || !req.url.startsWith('/')) {
      res.writeHead(400);
      return res.end();
    }
    const pathname = req.url.split('?')[0];

    if (pathname === '/__e2e/tunnel' && req.method === 'POST') return this.handleTunnel(req, res);
    if (pathname === '/__e2e/hello' && req.method === 'POST') return this.handleHello(req, res);
    if (pathname === '/__e2e/ping') {
      res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
      return res.end('ok');
    }
    if (pathname === '/__e2e/sw.js') {
      res.writeHead(200, {
        'content-type': 'application/javascript; charset=utf-8',
        'service-worker-allowed': '/',
        'cache-control': 'no-cache',
      });
      return res.end(SW_JS);
    }
    return this.sendBootPage(req, res);
  }

  sendBootPage(req, res) {
    const wantsPage = (req.method === 'GET' || req.method === 'HEAD')
      && (String(req.headers.accept || '').includes('text/html') || req.headers['sec-fetch-mode'] === 'navigate' || req.url.split('?')[0] === '/__e2e/boot');
    if (!wantsPage) {
      res.writeHead(401, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
      return res.end('Locked');
    }
    const nonce = crypto.randomBytes(16).toString('base64');
    const html = BOOT_HTML
      .replaceAll('{{NONCE}}', nonce)
      .replace('{{CONFIG}}', JSON.stringify({ salt: b64(this.salt), iterations: ITERATIONS }))
      .replace('{{SCRIPT}}', () => BOOT_JS);
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'x-robots-tag': 'noindex, nofollow',
      'content-security-policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; worker-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
    });
    res.end(req.method === 'HEAD' ? undefined : html);
  }

  readBody(req, limit = 8192) {
    return new Promise((resolve, reject) => {
      let raw = '';
      req.setEncoding('utf8');
      req.on('data', (chunk) => {
        raw += chunk;
        if (raw.length > limit) { req.destroy(); reject(new Error('too large')); }
      });
      req.on('end', () => resolve(raw));
      req.on('error', reject);
    });
  }

  /* ---------------- handshake ---------------- */

  async handleHello(req, res) {
    const ip = this.clientIp(req);
    const reply = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(body));
    };

    let body = {};
    try { body = JSON.parse(await this.readBody(req)); } catch { return reply(400, { error: 'Bad request' }); }

    if (this.pinFails.blocked(ip) || this.pinFailsGlobal.blocked('all')) {
      return reply(429, { error: 'Too many wrong PINs. Try again in 10 minutes.' });
    }

    const nonce = unb64(body.nc);
    const given = unb64(body.mac);
    const time = Number(body.t);
    if (nonce.length !== 32 || given.length !== 32 || !Number.isFinite(time)) return reply(400, { error: 'Bad request' });

    const expected = hmac(this.key, label('hello'), nonce, u64(time));
    if (!crypto.timingSafeEqual(expected, given)) {
      this.pinFails.add(ip);
      this.pinFailsGlobal.add('all');
      if (this.pinFails.blocked(ip) || this.pinFailsGlobal.blocked('all')) this.onLockout({ ip });
      return reply(403, { error: 'Wrong PIN.' });
    }

    const serverNonce = crypto.randomBytes(32);
    const sidBytes = crypto.randomBytes(16);
    const sid = b64(sidBytes);
    const now = Date.now();
    this.sessions.set(sid, {
      sid,
      sidBytes,
      key: hmac(this.key, label('session'), nonce, serverNonce),
      skew: now - time,
      created: now,
      lastSeen: now,
      ip,
      ua: String(req.headers['user-agent'] || ''),
      seen: new Map(),
      jar: new Map(),
      sockets: new Set(),
      streams: new Set(),
    });
    this.onUnlock({ ip, ua: req.headers['user-agent'] || '' });
    reply(200, { ns: b64(serverNonce), sid, mac: b64(hmac(this.key, label('welcome'), nonce, serverNonce, sidBytes)) });
  }

  /* ---------------- encrypted request tunnel ---------------- */

  async handleTunnel(req, res) {
    const session = this.sessions.get(String(req.headers['x-e2e-session'] || ''));
    if (!session) {
      res.writeHead(401, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      return res.end('{"error":"session"}');
    }
    const id = unb64(req.headers['x-e2e-request']);
    if (id.length !== 16) {
      res.writeHead(400);
      return res.end();
    }

    const frames = readFrames(req)[Symbol.asyncIterator]();
    let inIndex = 0;
    const nextFrame = async () => {
      const step = await frames.next();
      if (step.done) throw new Error('truncated');
      return unseal(session.key, step.value, Buffer.concat([label('req'), session.sidBytes, id, u32(inIndex++)]));
    };

    let first;
    try { first = await nextFrame(); } catch { res.writeHead(400); return res.end(); }

    let head;
    try { head = JSON.parse(first.data.toString('utf8')); } catch { res.writeHead(400); return res.end(); }

    const now = Date.now();
    const idKey = id.toString('base64');
    if (session.seen.has(idKey) || Math.abs(Number(head.t) + session.skew - now) > REPLAY_WINDOW_MS) {
      res.writeHead(409);
      return res.end();
    }
    session.seen.set(idKey, now);
    session.lastSeen = now;

    let outIndex = 0;
    const writeFrame = (flags, data) => res.write(seal(session.key, flags, data, Buffer.concat([label('res'), session.sidBytes, id, u32(outIndex++)])));

    res.writeHead(200, { 'content-type': 'application/octet-stream', 'cache-control': 'no-store', 'x-accel-buffering': 'no' });
    res.flushHeaders();
    session.streams.add(res);
    const keepAlive = setInterval(() => { if (!res.writableEnded) writeFrame(2, Buffer.alloc(0)); }, KEEPALIVE_MS);
    const finish = () => { clearInterval(keepAlive); session.streams.delete(res); };

    // The page helper asks for cookies the app's JavaScript needs to read
    if (head.u === '/__e2e_jar') {
      const jar = [...session.jar].filter(([, c]) => !c.httpOnly).map(([name, c]) => [name, c.value]);
      writeFrame(0, Buffer.from(JSON.stringify({ s: 200, st: 'OK', h: [['content-type', 'application/json']] })));
      writeFrame(0, Buffer.from(JSON.stringify(jar)));
      writeFrame(1, Buffer.alloc(0));
      finish();
      return res.end();
    }

    let upstream;
    try {
      upstream = http.request({
        host: this.target.host,
        port: this.target.port,
        method: head.m,
        path: head.u,
        headers: this.upstreamHeaders(head, session, req),
        agent: this.agent,
      });
    } catch {
      writeFrame(0, Buffer.from(JSON.stringify({ s: 400, st: 'Bad Request', h: [] })));
      writeFrame(1, Buffer.alloc(0));
      finish();
      return res.end();
    }

    let done = false;
    res.on('close', () => {
      finish();
      if (!done) upstream.destroy();
    });

    // Body frames -> upstream
    (async () => {
      let flags = first.flags;
      while (!(flags & 1)) {
        const part = await nextFrame();
        flags = part.flags;
        if (part.data.length && !upstream.write(part.data)) {
          await new Promise((resolve, reject) => {
            const cleanup = () => {
              upstream.off('drain', onDrain);
              upstream.off('error', onGone);
              upstream.off('close', onGone);
            };
            const onDrain = () => { cleanup(); resolve(); };
            const onGone = () => { cleanup(); reject(new Error('upstream gone')); };
            upstream.once('drain', onDrain);
            upstream.once('error', onGone);
            upstream.once('close', onGone);
          });
        }
      }
      upstream.end();
    })().catch(() => upstream.destroy());

    upstream.on('error', () => {
      if (res.writableEnded) return;
      if (outIndex === 0) {
        const offline = Buffer.from(`<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="3">`
          + `<title>Waiting for app</title><body style="font:16px system-ui;padding:32px;text-align:center;color:#444">`
          + `<h2>The app isn't responding yet</h2><p>Waiting for the app on this PC. Retrying every 3 seconds.</p>`);
        writeFrame(0, Buffer.from(JSON.stringify({ s: 502, st: 'Bad Gateway', h: [['content-type', 'text/html; charset=utf-8']] })));
        writeFrame(0, offline);
      }
      writeFrame(1, Buffer.alloc(0));
      finish();
      res.end();
    });

    // Wait for the socket to drain, without piling up listeners
    const drained = () => new Promise((resolve, reject) => {
      const cleanup = () => {
        res.off('drain', onDrain);
        res.off('close', onGone);
        res.off('error', onGone);
      };
      const onDrain = () => { cleanup(); resolve(); };
      const onGone = () => { cleanup(); reject(new Error('connection closed')); };
      res.once('drain', onDrain);
      res.once('close', onGone);
      res.once('error', onGone);
    });

    upstream.on('response', async (upRes) => {
      const meta = this.responseMeta(upRes, session, head);
      writeFrame(0, Buffer.from(JSON.stringify(meta)));
      const body = meta.z === 'gzip' ? upRes.pipe(zlib.createGzip({ flush: zlib.constants.Z_SYNC_FLUSH })) : upRes;

      try {
        for await (const chunk of body) {
          for (let at = 0; at < chunk.length; at += CHUNK) {
            if (!writeFrame(0, chunk.subarray(at, at + CHUNK))) await drained();
          }
        }
        done = true;
        writeFrame(1, Buffer.alloc(0));
        finish();
        res.end();
      } catch {
        finish();
        res.destroy();
      }
    });
  }

  upstreamHeaders(head, session, req) {
    const out = {};
    for (const [name, value] of head.h || []) {
      const lower = String(name).toLowerCase();
      if (DROP_HEADERS.has(lower) || lower.startsWith('x-e2e') || lower.startsWith('cf-') || lower === 'referer') continue;
      if (/[\r\n]/.test(String(value))) continue;
      out[lower] = value;
    }
    const referer = (head.h || []).find(([name]) => String(name).toLowerCase() === 'referer');
    if (referer && String(referer[1]).startsWith('/')) out.referer = this.targetOrigin + referer[1];

    out.host = this.hostHeader;
    out['accept-encoding'] = 'identity'; // we do our own compression inside the encryption
    out['user-agent'] = String(req.headers['user-agent'] || 'Share');
    if (head.m !== 'GET' && head.m !== 'HEAD') out.origin = this.targetOrigin;
    if (session.jar.size) out.cookie = [...session.jar].map(([name, c]) => `${name}=${c.value}`).join('; ');
    out['x-forwarded-host'] = String(req.headers.host || '');
    out['x-forwarded-proto'] = 'https';
    out['x-forwarded-for'] = session.ip;
    if (typeof head.bl === 'number') out['content-length'] = String(head.bl);
    return out;
  }

  responseMeta(upRes, session, head) {
    const headers = [];
    const mirror = [];
    let encoding = '';
    let length = null;
    let type = '';

    for (let i = 0; i < upRes.rawHeaders.length; i += 2) {
      const name = upRes.rawHeaders[i];
      const value = upRes.rawHeaders[i + 1];
      const lower = name.toLowerCase();
      if (['connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'proxy-connection'].includes(lower)) continue;
      if (lower === 'set-cookie') { this.storeCookie(session, value, mirror); continue; }
      if (lower === 'content-encoding') { encoding = String(value).toLowerCase(); }
      if (lower === 'content-length') { length = Number(value); }
      if (lower === 'content-type') { type = String(value); }
      if (lower === 'location') { headers.push([name, this.fixLocation(value)]); continue; }
      headers.push([name, value]);
    }

    const status = upRes.statusCode;
    const compress = head.m !== 'HEAD' && !NULL_BODY.has(status) && !encoding && COMPRESSIBLE.test(type) && !(length !== null && length < 1024);
    const out = {
      s: status,
      st: upRes.statusMessage || '',
      h: compress ? headers.filter(([name]) => name.toLowerCase() !== 'content-length') : headers,
      z: compress ? 'gzip' : null,
    };
    if (mirror.length) out.c = mirror;
    return out;
  }

  storeCookie(session, setCookie, mirror) {
    const [pair, ...attributes] = String(setCookie).split(';');
    const eq = pair.indexOf('=');
    if (eq < 1) return;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    const lower = attributes.map((a) => a.trim().toLowerCase());
    const httpOnly = lower.includes('httponly');
    const maxAge = lower.find((a) => a.startsWith('max-age='));
    const expires = attributes.find((a) => /^\s*expires=/i.test(a));
    const gone = (maxAge && Number(maxAge.slice(8)) <= 0)
      || (expires && Date.parse(expires.slice(expires.indexOf('=') + 1)) < Date.now());
    if (gone) session.jar.delete(name);
    else session.jar.set(name, { value, httpOnly });
    if (!httpOnly) mirror.push(gone ? [name, '', 1] : [name, value]);
  }

  fixLocation(location) {
    try {
      const url = new URL(location, this.targetOrigin);
      if (/^(127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)$/i.test(url.hostname) && String(url.port || 80) === String(this.target.port)) {
        return url.pathname + url.search + url.hash;
      }
    } catch { /* keep as-is */ }
    return location;
  }

  /* ---------------- encrypted WebSockets ---------------- */

  onUpgrade(req, socket, head) {
    socket.on('error', () => {});
    let url;
    try { url = new URL(req.url, 'http://share.local'); } catch { return socket.destroy(); }
    if (url.pathname !== '/__e2e/ws') {
      return socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    }
    const session = this.sessions.get(url.searchParams.get('s') || '');
    const conn = unb64(url.searchParams.get('c'));
    if (!session || conn.length !== 16) {
      return socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    }
    this.wss.handleUpgrade(req, socket, head, (ws) => this.bridgeWebSocket(ws, session, conn, req));
  }

  bridgeWebSocket(ws, session, conn, req) {
    session.sockets.add(ws);
    session.lastSeen = Date.now();
    let seqIn = 0;
    let seqOut = 0;
    let upstream = null;
    let closed = false;

    const aad = (dir, seq) => Buffer.concat([label('ws'), session.sidBytes, conn, Buffer.from([dir]), u32(seq)]);
    const send = (kind, payload) => {
      if (ws.readyState !== WebSocket.OPEN) return;
      const frame = seal(session.key, kind, payload, aad(1, seqOut++));
      ws.send(frame.subarray(4)); // WebSocket messages carry their own length
    };
    const sendControl = (obj) => send(0, Buffer.from(JSON.stringify(obj)));
    const shutdown = (code, reason) => {
      if (closed) return;
      closed = true;
      clearInterval(ping);
      session.sockets.delete(ws);
      if (upstream) { try { upstream.close(); } catch {} setTimeout(() => { try { upstream.terminate(); } catch {} }, 2000).unref(); }
      try { ws.close(code || 1000, reason || ''); } catch {}
    };
    const ping = setInterval(() => send(4, Buffer.alloc(0)), KEEPALIVE_MS);

    ws.on('message', (data, isBinary) => {
      if (!isBinary) return shutdown(1003, 'binary only');
      let part;
      try { part = unseal(session.key, Buffer.from(data), aad(0, seqIn++)); } catch { return shutdown(1008, 'bad frame'); }
      session.lastSeen = Date.now();

      if (!upstream) {
        if (part.flags !== 0) return shutdown(1008, 'expected open');
        let control;
        try { control = JSON.parse(part.data.toString('utf8')); } catch { return shutdown(1008, 'bad open'); }
        const connKey = conn.toString('base64');
        if (session.seen.has(connKey) || Math.abs(Number(control.t) + session.skew - Date.now()) > REPLAY_WINDOW_MS) {
          return shutdown(1008, 'replay');
        }
        session.seen.set(connKey, Date.now());
        const target = String(control.p || '/');
        if (!target.startsWith('/')) return shutdown(1008, 'bad path');

        const headers = {
          host: this.hostHeader,
          origin: this.targetOrigin,
          'user-agent': String(req.headers['user-agent'] || 'Share'),
          'x-forwarded-host': String(req.headers.host || ''),
          'x-forwarded-proto': 'https',
          'x-forwarded-for': session.ip,
        };
        if (session.jar.size) headers.cookie = [...session.jar].map(([name, c]) => `${name}=${c.value}`).join('; ');

        const protocols = Array.isArray(control.pr) && control.pr.length ? control.pr : undefined;
        upstream = new WebSocket(`ws://${this.hostHeader}${target}`, protocols, { headers, perMessageDeflate: false, handshakeTimeout: 15000 });
        upstream.binaryType = 'nodebuffer';

        upstream.on('open', () => sendControl({ type: 'open', protocol: upstream.protocol || '' }));
        upstream.on('message', (payload, binary) => send(binary ? 2 : 1, Buffer.from(payload)));
        upstream.on('close', (code, reason) => {
          send(3, Buffer.from(JSON.stringify({ code, reason: Buffer.from(reason || '').toString('utf8') })));
          shutdown(1000, '');
        });
        upstream.on('error', () => {
          send(3, Buffer.from(JSON.stringify({ code: 1006, reason: 'app not reachable' })));
          shutdown(1011, '');
        });
        return;
      }

      if (upstream.readyState !== WebSocket.OPEN) return;
      if (part.flags === 1) upstream.send(part.data.toString('utf8'));
      else if (part.flags === 2) upstream.send(part.data, { binary: true });
      else if (part.flags === 3) {
        let info = {};
        try { info = JSON.parse(part.data.toString('utf8')); } catch {}
        const code = Number(info.code);
        try { upstream.close(code === 1000 || (code >= 3000 && code <= 4999) ? code : 1000, String(info.reason || '')); } catch {}
      }
    });

    ws.on('close', () => shutdown());
    ws.on('error', () => shutdown());
  }
}

module.exports = { E2EShare };
