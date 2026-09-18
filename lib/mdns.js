// Tiny mDNS responder: answers "<name>.local" with this PC's current LAN IP,
// so the LAN link stays the same even when the router hands out a new IP.
const multicastDns = require('multicast-dns');

function startMdns(name, watcher, log = () => {}) {
  const host = `${name.toLowerCase()}.local`;
  let m;
  try {
    m = multicastDns({ reuseAddr: true, loopback: true });
  } catch (err) {
    log(`mDNS unavailable: ${err.message}`);
    return null;
  }

  const api = { host, ok: true };

  const answer = (ip) => m.respond({ answers: [{ name: host, type: 'A', ttl: 30, flush: true, data: ip }] });

  m.on('error', (err) => {
    api.ok = false;
    log(`mDNS error: ${err.message}`);
  });

  m.on('query', (query, rinfo) => {
    for (const q of query.questions || []) {
      if (String(q.name).toLowerCase() !== host || (q.type !== 'A' && q.type !== 'ANY')) continue;
      const ip = watcher.ipFacing(rinfo.address);
      if (ip) answer(ip);
    }
  });

  // Re-join multicast on new adapters and tell caches about the new address
  api.announce = () => {
    try {
      m.update();
      if (watcher.current.primary) answer(watcher.current.primary);
    } catch {}
  };

  api.stop = () => { try { m.destroy(); } catch {} };
  return api;
}

module.exports = { startMdns };
