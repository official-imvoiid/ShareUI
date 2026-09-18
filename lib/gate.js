// PIN lock for the local network link: nobody on your Wi-Fi reaches the app without the PIN.
// (The internet link uses lib/e2e.js instead, which also encrypts everything end-to-end.)
const crypto = require('crypto');

const WINDOW_MS = 10 * 60 * 1000;
const COOKIE = 'share_session';

function samePin(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

class Limiter {
  constructor(max) { this.max = max; this.hits = new Map(); }
  recent(id) {
    const now = Date.now();
    const list = (this.hits.get(id) || []).filter((t) => now - t < WINDOW_MS);
    if (list.length) this.hits.set(id, list); else this.hits.delete(id);
    return list;
  }
  blocked(id) { return this.recent(id).length >= this.max; }
  add(id) { const list = this.recent(id); list.push(Date.now()); this.hits.set(id, list); }
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}

class PinGate {
  constructor({ pin, secret, enabled = true, ttlSec = 30 * 86400, onUnlock = () => {}, onLockout = () => {} }) {
    this.enabled = enabled; // the local link may be shared without a PIN
    this.secret = secret || crypto.randomBytes(32).toString('base64url');
    this.ttlSec = ttlSec;
    this.onUnlock = onUnlock;
    this.onLockout = onLockout;
    this.devices = new Map();
    this.fails = new Limiter(5);
    this.failsGlobal = new Limiter(20);
    this.setPin(pin);
  }

  get cookieName() { return COOKIE; }

  setPin(pin) {
    this.pin = String(pin);
    this.signingKey = crypto.createHash('sha256').update(`share-pin/1\0${this.secret}\0${this.pin}`).digest();
    this.devices.clear();
  }

  sign(payload) { return crypto.createHmac('sha256', this.signingKey).update(payload).digest('base64url'); }

  issue() {
    const payload = `${Math.floor(Date.now() / 1000)}.${crypto.randomBytes(12).toString('base64url')}`;
    return `${payload}.${this.sign(payload)}`;
  }

  check(req, ip) {
    if (!this.enabled) return true;
    const token = parseCookies(req.headers.cookie)[COOKIE];
    if (!token) return false;
    const [issued, id, mac] = token.split('.');
    if (!mac || !/^\d+$/.test(issued || '') || Date.now() / 1000 - Number(issued) > this.ttlSec) return false;
    const expected = Buffer.from(this.sign(`${issued}.${id}`));
    const given = Buffer.from(mac);
    if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) return false;
    const seen = this.devices.get(id);
    if (seen) seen.lastSeen = Date.now();
    else this.devices.set(id, { ip, ua: String(req.headers['user-agent'] || '').slice(0, 160), lastSeen: Date.now() });
    return true;
  }

  activeDevices(withinMs = 5 * 60 * 1000) {
    const now = Date.now();
    return [...this.devices.values()].filter((d) => now - d.lastSeen < withinMs).length;
  }

  stripCookie(header) {
    if (!header) return header;
    return String(header).split(';').filter((part) => part.split('=')[0].trim() !== COOKIE).join(';').trim();
  }

  handleAuth(req, res, ip) {
    const reply = (status, body, extra = {}) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...extra });
      res.end(JSON.stringify(body));
    };
    if (req.method !== 'POST') return reply(405, { error: 'POST only' });

    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => { raw += chunk; if (raw.length > 4096) req.destroy(); });
    req.on('end', () => {
      let body = {};
      try { body = JSON.parse(raw || '{}'); } catch {}

      if (this.fails.blocked(ip) || this.failsGlobal.blocked('all')) {
        return reply(429, { error: 'Too many wrong PINs. Try again in 10 minutes.' });
      }
      if (!body.pin || !samePin(body.pin, this.pin)) {
        this.fails.add(ip);
        this.failsGlobal.add('all');
        if (this.fails.blocked(ip) || this.failsGlobal.blocked('all')) this.onLockout({ ip });
        return reply(403, { error: 'Wrong PIN.' });
      }
      this.onUnlock({ ip, ua: req.headers['user-agent'] || '' });
      reply(200, { ok: true }, {
        'set-cookie': `${COOKIE}=${this.issue()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${this.ttlSec}`,
      });
    });
  }

  logout(res) {
    res.writeHead(302, {
      location: '/',
      'cache-control': 'no-store',
      'set-cookie': `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
    });
    res.end();
  }
}

module.exports = { PinGate };
