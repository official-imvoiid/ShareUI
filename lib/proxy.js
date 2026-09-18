// Local network proxy: puts ONE local app port on your Wi-Fi, behind the PIN.
// Nothing else on your PC is reachable through it.
const fs = require('fs');
const http = require('http');
const path = require('path');
const crypto = require('crypto');

// http-proxy calls util._extend, which newer Node versions warn about on every run; silence just that one
const emitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
  if (args[1] === 'DEP0060' || (args[0] && args[0].code === 'DEP0060')) return;
  return emitWarning.call(process, warning, ...args);
};

const httpProxy = require('http-proxy');

const GATE_HTML = fs.readFileSync(path.join(__dirname, '..', 'public', 'gate.html'), 'utf8');
const HOP_BY_HOP = ['connection', 'keep-alive', 'proxy-connection', 'upgrade'];
const LOCAL_HOST_RE = /^(127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)$/i;

function offlinePage(port) {
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="3"><title>Waiting for app</title>
<body style="font:16px system-ui,sans-serif;display:grid;place-items:center;min-height:90vh;margin:0 16px;color:#333;background:#f6f6f4">
<div style="text-align:center"><h2 style="margin:0 0 8px">The app isn't responding yet</h2>
<p style="margin:0;color:#666">Waiting for the app on port ${port}. This page retries every 3 seconds.</p></div>`;
}

function createShareServer({ target, gate, onEvent = () => {} }) {
  const urlHost = target.host.includes(':') ? `[${target.host}]` : target.host;
  const targetOrigin = `http://${urlHost}:${target.port}`;
  const hostHeader = target.host === '::1' ? `localhost:${target.port}` : `${urlHost}:${target.port}`;
  const clientIp = (req) => String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');

  const agent = new http.Agent({ keepAlive: true, maxSockets: 256 });
  const proxy = httpProxy.createProxyServer({
    target: targetOrigin,
    agent,
    ws: true,
    xfwd: false,
    selfHandleResponse: true,
    proxyTimeout: 0,
    timeout: 0,
  });

  // Make the app believe it's being opened locally (Gradio/Streamlit/Vite reject foreign Host/Origin)
  function rewriteRequest(proxyReq, req) {
    proxyReq.setHeader('host', hostHeader);
    if (req.headers.origin) proxyReq.setHeader('origin', targetOrigin);
    if (req.headers.referer) {
      try {
        const ref = new URL(req.headers.referer);
        proxyReq.setHeader('referer', targetOrigin + ref.pathname + ref.search);
      } catch {
        proxyReq.removeHeader('referer');
      }
    }
    proxyReq.setHeader('x-forwarded-host', req.headers.host || '');
    proxyReq.setHeader('x-forwarded-proto', 'http');
    proxyReq.setHeader('x-forwarded-for', clientIp(req));

    const cookie = gate.stripCookie(req.headers.cookie);
    if (cookie) proxyReq.setHeader('cookie', cookie); else proxyReq.removeHeader('cookie');
  }

  proxy.on('proxyReq', rewriteRequest);
  proxy.on('proxyReqWs', rewriteRequest);

  function fixLocation(location) {
    try {
      const url = new URL(location, targetOrigin);
      if (LOCAL_HOST_RE.test(url.hostname) && String(url.port || 80) === String(target.port)) {
        return url.pathname + url.search + url.hash;
      }
    } catch { /* keep as-is */ }
    return location;
  }

  function fixCookie(cookie) {
    return cookie
      .replace(/;\s*domain=(localhost|127\.0\.0\.1)\s*(?=;|$)/gi, '')
      .replace(/;\s*secure\s*(?=;|$)/gi, ''); // the local link is plain http
  }

  proxy.on('proxyRes', (proxyRes, req, res) => {
    const headers = { ...proxyRes.headers };
    for (const name of HOP_BY_HOP) delete headers[name];
    if (headers.location) headers.location = fixLocation(headers.location);
    if (headers['set-cookie']) headers['set-cookie'] = headers['set-cookie'].map(fixCookie);

    const isStream = String(headers['content-type'] || '').includes('text/event-stream');
    if (isStream) {
      headers['x-accel-buffering'] = 'no';
      if (!headers['cache-control']) headers['cache-control'] = 'no-cache';
    }
    res.writeHead(proxyRes.statusCode, headers);
    if (isStream) res.flushHeaders();
    proxyRes.pipe(res);
  });

  let lastRefused = 0;
  proxy.on('error', (err, req, res) => {
    if (err.code === 'ECONNREFUSED' && Date.now() - lastRefused > 10000) {
      lastRefused = Date.now();
      onEvent('upstream-down', err);
    }
    if (res && typeof res.writeHead === 'function') {
      if (res.headersSent) return res.destroy();
      const wantsHtml = String(req.headers.accept || '').includes('text/html');
      res.writeHead(502, { 'content-type': wantsHtml ? 'text/html; charset=utf-8' : 'text/plain', 'cache-control': 'no-store' });
      res.end(wantsHtml ? offlinePage(target.port) : `The app on port ${target.port} is not responding.`);
    } else if (res && typeof res.destroy === 'function') {
      res.destroy(); // res is a Socket on WebSocket failures
    }
  });

  function sendGate(req, res) {
    const accept = String(req.headers.accept || '');
    const isPage = req.method === 'GET' && (accept.includes('text/html') || req.headers['sec-fetch-mode'] === 'navigate');
    if (!isPage) {
      res.writeHead(401, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
      return res.end('PIN needed');
    }
    const nonce = crypto.randomBytes(16).toString('base64');
    res.writeHead(401, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'x-robots-tag': 'noindex, nofollow',
      'content-security-policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
    });
    res.end(GATE_HTML.replaceAll('{{NONCE}}', nonce));
  }

  const server = http.createServer((req, res) => {
    if (!req.url.startsWith('/')) { // absolute-form URLs could be used to probe other hosts
      res.writeHead(400);
      return res.end();
    }
    const pathname = req.url.split('?')[0];
    if (pathname === '/__share/auth') return gate.handleAuth(req, res, clientIp(req));
    if (pathname === '/__share/logout') return gate.logout(res);
    if (!gate.check(req, clientIp(req))) return sendGate(req, res);
    proxy.web(req, res);
  });

  const wsSockets = new Set();
  server.on('upgrade', (req, socket, head) => {
    socket.on('error', () => {});
    if (!req.url.startsWith('/') || !gate.check(req, clientIp(req))) {
      return socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    }
    wsSockets.add(socket);
    socket.on('close', () => wsSockets.delete(socket));
    proxy.ws(req, socket, head, { agent: false });
  });

  server.headersTimeout = 60000;
  server.requestTimeout = 0; // big uploads / long generations
  server.keepAliveTimeout = 65000;

  function listen(host, port, tries = 1) {
    return new Promise((resolve, reject) => {
      const attempt = (p, left) => {
        const onError = (err) => {
          server.off('listening', onListening);
          if (err.code === 'EADDRINUSE' && left > 1) attempt(p + 1, left - 1);
          else reject(err);
        };
        const onListening = () => {
          server.off('error', onError);
          resolve(server.address().port);
        };
        server.once('error', onError);
        server.once('listening', onListening);
        server.listen(p, host);
      };
      attempt(port, tries);
    });
  }

  function kickAll() {
    for (const socket of wsSockets) socket.destroy();
    wsSockets.clear();
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
  }

  return {
    server,
    listen,
    kickAll,
    close() {
      kickAll();
      server.close();
      agent.destroy();
    },
  };
}

module.exports = { createShareServer };
