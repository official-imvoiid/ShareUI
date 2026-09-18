// Finds web apps listening on this PC (Gradio, Streamlit, Vite, Next.js, ComfyUI, Jupyter, anything HTTP).
const net = require('net');
const http = require('http');
const { execFile } = require('child_process');

const COMMON_PORTS = [80, 3000, 3001, 4200, 5000, 5173, 5174, 7860, 7861, 7862, 7863, 8000, 8080, 8081, 8188, 8501, 8502, 8888, 9000];
const SKIP_PROCESSES = /^(system|idle|svchost|lsass|wininit|services|spoolsv|cloudflared|mdnsresponder|searchhost)(\.exe)?$/i;
const SKIP_PORTS = new Set([135, 139, 445, 5040, 5353, 5357, 7680]);

function run(cmd, args) {
  return new Promise((resolve) => {
    execFile(cmd, args, { windowsHide: true, timeout: 5000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => {
      resolve(err ? '' : String(stdout));
    });
  });
}

async function listeningWindows() {
  const [netstat, tasklist] = await Promise.all([run('netstat', ['-ano']), run('tasklist', ['/fo', 'csv', '/nh'])]);
  const names = new Map();
  for (const line of tasklist.split(/\r?\n/)) {
    const m = /^"([^"]+)","(\d+)"/.exec(line);
    if (m) names.set(Number(m[2]), m[1]);
  }
  const found = new Map();
  for (const line of netstat.split(/\r?\n/)) {
    // Foreign address 0.0.0.0:0 / [::]:0 means LISTENING (the state word itself is translated on non-English Windows)
    const m = /^\s*TCP\s+(\S+):(\d+)\s+(?:0\.0\.0\.0:0|\[::\]:0)\s+\S+\s+(\d+)\s*$/i.exec(line);
    if (!m) continue;
    const [, addr, port, pid] = m;
    if (!/^(127\.|0\.0\.0\.0|\[::\]|\[::1\])/.test(addr)) continue;
    const entry = found.get(Number(port)) || { port: Number(port), pid: Number(pid), process: names.get(Number(pid)) || '', v6only: true };
    if (!addr.startsWith('[')) entry.v6only = false;
    found.set(Number(port), entry);
  }
  return [...found.values()];
}

async function listeningUnix() {
  const out = await run('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN']);
  const found = new Map();
  for (const line of out.split('\n').slice(1)) {
    const cols = line.trim().split(/\s+/);
    const m = /(?:^|:)(\d+)$/.exec(cols[8] || '');
    if (!m) continue;
    const addr = cols[8];
    if (!/^(127\.|\*|\[::1\]|\[::\]|localhost)/.test(addr)) continue;
    found.set(Number(m[1]), { port: Number(m[1]), pid: Number(cols[1]), process: cols[0], v6only: addr.startsWith('[::1]') });
  }
  return [...found.values()];
}

function probe(host, port) {
  return new Promise((resolve) => {
    const req = http.get({ host, port, path: '/', timeout: 1500, headers: { accept: 'text/html,*/*', 'user-agent': 'share-probe' } }, (res) => {
      let body = '';
      res.setEncoding('latin1');
      res.on('data', (c) => {
        if (body.length < 96 * 1024) body += c;
      });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
      res.on('error', () => resolve(null));
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
  });
}

function classify({ status, headers, body }) {
  const server = String(headers.server || '');
  const title = (/<title[^>]*>([^<]{1,80})<\/title>/i.exec(body) || [])[1];
  const kinds = [
    [/gradio_config|gradio-app|__gradio|gradio\.js/i, 'Gradio'],
    [/streamlit/i, 'Streamlit'],
    [/comfyui/i, 'ComfyUI'],
    [/\/@vite\/client/, 'Vite'],
    [/__NEXT_DATA__|\/_next\/static/, 'Next.js'],
    [/jupyter/i, 'Jupyter'],
    [/ng-version|<app-root/i, 'Angular'],
  ];
  const kind = (kinds.find(([re]) => re.test(body)) || [])[1]
    || (/express/i.test(String(headers['x-powered-by'] || '')) && 'Express')
    || (/uvicorn|hypercorn/i.test(server) && 'Python (ASGI)')
    || (/werkzeug/i.test(server) && 'Flask')
    || 'Web app';
  // Something you would actually open in a browser: a known framework, or a page that answers with HTML.
  // Helper processes and background bridges answer 404 / plain text, so they stay out of the list.
  const servesPage = status < 400 && /text\/html/i.test(String(headers['content-type'] || ''));
  return { kind, title: title ? title.trim().replace(/\s+/g, ' ') : '', isApp: kind !== 'Web app' || servesPage };
}

async function discover(excludePorts = []) {
  let listening = process.platform === 'win32' ? await listeningWindows() : await listeningUnix();
  if (!listening.length) listening = COMMON_PORTS.map((port) => ({ port, pid: 0, process: '', v6only: false }));

  const skip = new Set(excludePorts);
  const candidates = listening.filter((e) => !SKIP_PORTS.has(e.port) && !skip.has(e.port)
    && e.pid !== process.pid && !SKIP_PROCESSES.test(e.process) && e.pid !== 4);

  const results = await Promise.all(candidates.map(async (e) => {
    const host = e.v6only ? '::1' : '127.0.0.1';
    const res = await probe(host, e.port);
    if (!res) return null;
    return { ...e, host, ...classify(res) };
  }));

  return results.filter(Boolean).sort((a, b) => (b.isApp - a.isApp) || (a.kind === 'Web app') - (b.kind === 'Web app') || a.port - b.port);
}

// What kind of app is on this port? (for ports typed on the command line)
async function describe(host, port) {
  const res = await probe(host, port);
  return res ? classify(res) : { kind: '', title: '', isApp: true };
}

// Is anything listening on the target port right now? (plain TCP connect, so it doesn't spam app logs)
function isUp(host, port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const done = (up) => { socket.destroy(); resolve(up); };
    socket.setTimeout(1500, () => done(false));
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
  });
}

module.exports = { discover, describe, isUp };
