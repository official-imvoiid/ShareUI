// LAN IP detection + a background watcher that notices when the IP changes (DHCP, Wi-Fi switch, hotspot...).
const os = require('os');
const dgram = require('dgram');
const { EventEmitter } = require('events');

// Adapters that exist but aren't your real Wi-Fi/Ethernet (VMs, containers, VPNs, Bluetooth PAN)
const VIRTUAL_RE = /(vmware|virtualbox|vbox|docker|vethernet|hyper-v|wsl|loopback|npcap|tailscale|zerotier|wireguard|openvpn|tap-|\btun|utun|ppp|hamachi|radmin|bluetooth|br-|veth|virbr|nordlynx|mullvad|proton)/i;

function rank(ip) {
  if (ip.startsWith('192.168.')) return 0; // typical home Wi-Fi
  if (ip.startsWith('10.')) return 1;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return 2;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return 5; // CGNAT / Tailscale range
  return 4;
}

function listIPv4() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      // Node <18 reports family as 'IPv4', newer versions may report 4
      const isV4 = a.family === 'IPv4' || a.family === 4;
      if (!isV4 || a.internal || a.address.startsWith('169.254.')) continue; // skip link-local, useless
      out.push({ name, ip: a.address, netmask: a.netmask, virtual: VIRTUAL_RE.test(name) });
    }
  }
  out.sort((x, y) => (x.virtual - y.virtual) || (rank(x.ip) - rank(y.ip)));
  return out;
}

// The address the OS would use to reach the internet. UDP connect() sends no packets.
function routeIP() {
  return new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    let finished = false;
    const done = (ip) => {
      if (finished) return;
      finished = true;
      try { s.close(); } catch {}
      resolve(ip);
    };
    s.on('error', () => done(null));
    s.connect(53, '1.1.1.1', () => {
      try { done(s.address().address); } catch { done(null); }
    });
    setTimeout(() => done(null), 500).unref();
  });
}

async function snapshot() {
  const all = listIPv4();
  const viaRoute = await routeIP();
  const routed = all.find((a) => a.ip === viaRoute && !a.virtual);
  const best = routed || all.find((a) => !a.virtual) || all[0] || null;
  return { primary: best ? best.ip : null, iface: best ? best.name : null, all };
}

function toInt(ip) {
  return ip.split('.').reduce((n, part) => (n * 256) + Number(part), 0) >>> 0;
}

function sameSubnet(a, b, mask) {
  try { return ((toInt(a) & toInt(mask)) >>> 0) === ((toInt(b) & toInt(mask)) >>> 0); } catch { return false; }
}

class NetworkWatcher extends EventEmitter {
  constructor(intervalMs = 3000) {
    super();
    this.intervalMs = intervalMs;
    this.current = { primary: null, iface: null, all: [] };
    this.sig = '';
  }

  async start() {
    await this.check();
    this.timer = setInterval(() => this.check().catch(() => {}), this.intervalMs);
    this.timer.unref();
  }

  async check() {
    const snap = await snapshot();
    const sig = JSON.stringify([snap.primary, snap.all.map((a) => a.ip)]);
    if (sig === this.sig) return;
    const prev = this.current;
    this.sig = sig;
    this.current = snap;
    if (prev.all.length || prev.primary) this.emit('change', snap, prev);
  }

  // Our IP on the same subnet as a remote device (right answer when several adapters are up)
  ipFacing(remote) {
    const hit = this.current.all.find((a) => a.netmask && sameSubnet(a.ip, remote, a.netmask));
    return hit ? hit.ip : this.current.primary;
  }

  stop() { clearInterval(this.timer); }
}

module.exports = { NetworkWatcher, listIPv4 };
