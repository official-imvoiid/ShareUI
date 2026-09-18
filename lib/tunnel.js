// Runs a Cloudflare quick tunnel (no account) to the local share proxy and keeps it alive.
const fs = require('fs');
const os = require('os');
const dns = require('dns');
const path = require('path');
const { spawn } = require('child_process');
const { EventEmitter } = require('events');

const URL_RE = /https:\/\/(?!api\.)[a-z0-9-]+\.trycloudflare\.com/i;

function findCloudflared() {
  const exe = process.platform === 'win32' ? 'cloudflared.exe' : 'cloudflared';
  const candidates = [
    process.env.CLOUDFLARED_PATH,
    path.join(__dirname, '..', 'bin', exe),
    ...(process.env.PATH || '').split(path.delimiter).filter(Boolean).map((dir) => path.join(dir, exe)),
  ];
  if (process.platform === 'win32') {
    candidates.push(
      'C:\\Program Files (x86)\\cloudflared\\cloudflared.exe',
      'C:\\Program Files\\cloudflared\\cloudflared.exe',
      path.join(process.env.LOCALAPPDATA || '', 'Microsoft', 'WinGet', 'Links', 'cloudflared.exe'),
    );
  } else {
    candidates.push('/opt/homebrew/bin/cloudflared', '/usr/local/bin/cloudflared', '/usr/bin/cloudflared');
  }
  return candidates.find((p) => {
    try { return p && fs.statSync(p).isFile(); } catch { return false; }
  }) || null;
}

// Quick tunnels refuse to start when ~/.cloudflared/config.yml exists; point them at a minimal config instead
// (a completely empty file is rejected by cloudflared)
function configOverride() {
  const home = path.join(os.homedir(), '.cloudflared');
  const exists = ['config.yml', 'config.yaml'].some((f) => fs.existsSync(path.join(home, f)));
  if (!exists) return [];
  const minimal = path.join(os.tmpdir(), 'share-quick-tunnel.yml');
  try { fs.writeFileSync(minimal, 'no-autoupdate: true\n'); } catch {}
  return ['--config', minimal];
}

// Resolve through public DNS first so Windows doesn't cache a "not found" for the brand-new hostname
async function waitForDns(host, timeoutMs = 60000) {
  const resolver = new dns.promises.Resolver({ timeout: 2000, tries: 1 });
  resolver.setServers(['1.1.1.1', '8.8.8.8']);
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    try {
      if ((await resolver.resolve4(host)).length) return true;
    } catch {}
    await new Promise((r) => setTimeout(r, 1500));
  }
  return false;
}

class QuickTunnel extends EventEmitter {
  constructor({ bin, localPort }) {
    super();
    this.bin = bin;
    this.localPort = localPort;
    this.status = 'stopped'; // starting | live | reconnecting | error | stopped
    this.url = null;
    this.verified = false;
    this.error = null;
    this.logTail = [];
    this.restarts = 0;
  }

  setStatus(status, error = null) {
    this.status = status;
    this.error = error;
    this.emit('status', this);
  }

  start() {
    this.stopping = false;
    this.url = null;
    this.verified = false;
    this.setStatus(this.restarts ? 'reconnecting' : 'starting');

    const args = ['tunnel', '--no-autoupdate', ...configOverride(), '--url', `http://127.0.0.1:${this.localPort}`];
    const child = spawn(this.bin, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    this.child = child;

    const noUrlTimer = setTimeout(() => {
      if (!this.url) {
        this.lastError = 'Could not get a tunnel from Cloudflare (no internet, firewall, or trycloudflare is busy).';
        child.kill();
      }
    }, 45000);

    let pending = '';
    const onData = (buf) => {
      pending += buf.toString();
      const lines = pending.split(/\r?\n/);
      pending = lines.pop();
      for (const line of lines) this.onLine(line);
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);

    child.on('error', (err) => {
      this.lastError = err.message;
    });

    child.on('exit', (code) => {
      clearTimeout(noUrlTimer);
      if (this.child === child) this.child = null;
      if (this.stopping) return this.setStatus('stopped');
      this.restarts += 1;
      const wait = Math.min(30000, 2000 * 2 ** Math.min(this.restarts - 1, 4));
      const why = /quick tunnel|429|trycloudflare/i.test(this.lastError || '')
        ? 'Cloudflare did not hand out a tunnel (trycloudflare busy or no internet).'
        : this.lastError && this.lastError.startsWith('Could not') ? this.lastError
          : `Tunnel connection lost (cloudflared exited, code ${code}).`;
      this.url = null;
      this.setStatus('reconnecting', `${why} Retrying in ${Math.round(wait / 1000)}s…`);
      this.retryTimer = setTimeout(() => this.start(), wait);
    });
  }

  onLine(line) {
    const clean = line.replace(/\x1b\[[0-9;]*m/g, '').trim();
    if (!clean) return;
    this.logTail.push(clean);
    if (this.logTail.length > 40) this.logTail.shift();

    const found = !this.url && URL_RE.exec(clean);
    if (found) {
      this.url = found[0].toLowerCase();
      this.emit('url', this.url);
    }
    if (/\sERR\s/.test(clean)) this.lastError = clean.replace(/^\S+\s+ERR\s+/, '').slice(0, 200);
    if (/Registered tunnel connection/i.test(clean) && this.url && this.status !== 'live') {
      this.restarts = 0;
      this.lastError = null;
      this.setStatus('live');
      this.verify(this.url);
    }
  }

  async verify(url) {
    const host = new URL(url).hostname;
    await new Promise((r) => setTimeout(r, 2000));
    const resolved = await waitForDns(host);
    if (!resolved || this.url !== url) return;
    for (let i = 0; i < 20 && this.url === url; i++) {
      try {
        const res = await fetch(`${url}/__e2e/ping`, { signal: AbortSignal.timeout(5000) });
        if (res.ok) {
          this.verified = true;
          this.emit('status', this);
          return;
        }
      } catch {}
      await new Promise((r) => setTimeout(r, 2000));
    }
  }

  stop() {
    this.stopping = true;
    clearTimeout(this.retryTimer);
    if (this.child) this.child.kill();
  }
}

module.exports = { QuickTunnel, findCloudflared };
