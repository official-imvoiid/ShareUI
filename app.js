#!/usr/bin/env node
// Share — share a localhost app (ComfyUI, Gradio, Streamlit, Node, ...) on your local network,
// or over the internet end-to-end encrypted. Everything runs inside this terminal window.
// One app per window: open Share again to share a second app (it gets its own port automatically).
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { spawn, execFile } = require('child_process');

const config = require('./lib/config');
const qr = require('./lib/qr');
const { PinGate } = require('./lib/gate');
const { E2EShare } = require('./lib/e2e');
const { NetworkWatcher } = require('./lib/network');
const { startMdns } = require('./lib/mdns');
const { createShareServer } = require('./lib/proxy');
const { QuickTunnel, findCloudflared } = require('./lib/tunnel');
const { discover, describe, isUp } = require('./lib/ports');

/* ---------------- terminal helpers ---------------- */

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const c = { bold: paint(1), dim: paint(2), green: paint(32), yellow: paint(33), red: paint(31), cyan: paint(36), inverse: paint(7) };
// Symbols that exist in the default cmd.exe font (no emoji)
const sym = { ok: c.green('√'), warn: c.yellow('!'), info: c.cyan('»'), live: c.green('●'), off: c.yellow('●') };
const log = (...parts) => console.log(...parts);
const rule = () => log(c.dim('  ' + '─'.repeat(66)));
const indent = (block) => block.replace(/\n+$/, '').split('\n').map((line) => `    ${line}`).join('\n');

let menuRl = null;
function ask(question) {
  if (!menuRl) {
    menuRl = readline.createInterface({ input: process.stdin, output: process.stdout });
    menuRl.on('SIGINT', () => process.exit(0));
  }
  return new Promise((resolve) => menuRl.question(question, (answer) => resolve(answer.trim())));
}
function closeMenu() {
  if (menuRl) menuRl.close();
  menuRl = null;
}

function copyToClipboard(text) {
  const [cmd, args] = process.platform === 'win32' ? ['clip', []]
    : process.platform === 'darwin' ? ['pbcopy', []] : ['xclip', ['-selection', 'clipboard']];
  return new Promise((resolve) => {
    try {
      const child = spawn(cmd, args, { stdio: ['pipe', 'ignore', 'ignore'], windowsHide: true });
      child.on('error', () => resolve(false));
      child.on('exit', (code) => resolve(code === 0));
      child.stdin.end(text);
    } catch {
      resolve(false);
    }
  });
}

function deviceName(ua) {
  if (/iphone/i.test(ua)) return 'iPhone';
  if (/ipad/i.test(ua)) return 'iPad';
  if (/android/i.test(ua)) return 'Android';
  if (/windows/i.test(ua)) return 'Windows PC';
  if (/macintosh|mac os/i.test(ua)) return 'Mac';
  if (/linux/i.test(ua)) return 'Linux';
  return 'A device';
}

// "ComfyUI" with the title "ComfyUI" should not be printed twice
function appLabel(target) {
  const kind = target.kind || '';
  const title = (target.title || '').trim();
  if (!title) return kind || `port ${target.port}`;
  if (!kind) return title;
  const a = kind.toLowerCase();
  const b = title.toLowerCase();
  if (a === b || b.includes(a) || a.includes(b)) return title.length >= kind.length ? title : kind;
  return `${kind} "${title}"`;
}

const slug = (text) => String(text).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'app';

/* ---------------- arguments ---------------- */

function parseArgs(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    switch (k) {
      case '-p': case '--port': a.port = Number(argv[++i]); break;
      case '--host': a.host = argv[++i]; break;
      case '--lan': a.mode = a.mode === 'cloud' ? 'both' : 'lan'; break;
      case '--cloud': a.mode = a.mode === 'lan' ? 'both' : 'cloud'; break;
      case '--both': a.mode = 'both'; break;
      case '--lan-port': a.lanPort = Number(argv[++i]); break;
      case '--pin': a.pin = argv[++i] || ''; break;
      case '--no-pin': a.lanPin = false; break;
      case '--lan-pin': a.lanPin = true; break;
      case '-h': case '--help': a.help = true; break;
      default:
        if (/^\d+$/.test(k)) a.port = Number(k);
        else { log(c.red(`Unknown option: ${k}`)); a.help = true; }
    }
  }
  return a;
}

function printHelp() {
  log(`
  ${c.bold('Share')} - share a localhost app on your network or the internet

  ${c.bold('Usage')}
    node app.js                      interactive menu
    node app.js 8188 --lan           share port 8188 on your local network
    node app.js 8188 --cloud         share port 8188 over the internet, end-to-end encrypted
    node app.js 8188 --both          both ways

  One app per window. To share a second app, open Share again in another window:
  it picks the next free port on its own and remembers it.

  ${c.bold('Options')}
    -p, --port <n>     app port on this PC
    --host <addr>      app address (default 127.0.0.1)
    --lan-port <n>     first port for the local link (default 8000, remembered per app)
    --pin <pin>        PIN visitors must type (4-12 digits, remembered)
    --no-pin           no PIN on the local links (the internet link always needs one)
`);
}

/* ---------------- start-up menus ---------------- */

async function pickTarget(args, settings, interactive) {
  const host = args.host || '127.0.0.1';
  const withInfo = async (port) => ({ host, port, ...(await describe(host, port)) });

  if (args.port || !interactive) return withInfo(args.port || settings.targetPort);

  log(c.dim('  Looking for apps running on this PC...'));
  const apps = await discover(Object.values(settings.lanPorts || {}).concat(settings.lanPort));

  const manual = async () => {
    const answer = await ask(`  Port to share [${settings.targetPort}]: `);
    return withInfo(Number(answer) || settings.targetPort);
  };

  if (!apps.length) {
    log(`\n  ${c.yellow('No running web apps found.')} ${c.dim('Start your app first, or type its port.')}`);
    return manual();
  }

  // Background helpers (bridges, updaters, dev tools) listen on ports too - they are not apps, so drop them
  const shown = apps.filter((app) => app.isApp);
  if (!shown.length) {
    log(`\n  ${c.yellow('No running web apps found.')} ${c.dim('Start your app first, or type its port.')}`);
    return manual();
  }

  log(`\n  ${c.bold('Apps running on this PC')}`);
  shown.forEach((app, i) => {
    log(`   ${c.cyan(String(i + 1).padStart(2))}  ${c.bold(`:${app.port}`.padEnd(7))} ${appLabel(app).padEnd(34)} ${c.dim(app.process)}`);
  });
  log(`   ${c.cyan(' 0')}  Type a port number`);

  const fallback = Math.max(0, shown.findIndex((a) => a.port === settings.targetPort)) + 1;
  const answer = await ask(`\n  Choose app [${fallback}]: `);
  const pick = answer === '' ? fallback : Number(answer);

  if (pick >= 1 && pick <= shown.length) return shown[pick - 1];
  if (pick > 80) return withInfo(pick);
  return manual();
}

async function pickMode(settings) {
  const modes = ['lan', 'cloud', 'both'];
  log(`\n  ${c.bold('How do you want to share?')}`);
  log(`   ${c.cyan('1')}  Local network   ${c.dim('same Wi-Fi / LAN only, never leaves your network')}`);
  log(`   ${c.cyan('2')}  Internet        ${c.dim('end-to-end encrypted, Cloudflare only relays scrambled data')}`);
  log(`   ${c.cyan('3')}  Both`);
  const fallback = modes.indexOf(settings.lastMode) + 1 || 1;
  const answer = await ask(`\n  Choose [${fallback}]: `);
  return modes[(Number(answer) || fallback) - 1] || 'lan';
}

// The internet link always needs a PIN; on the local network it is optional.
async function askPin(settings, args, mode, interactive) {
  if (args.pin !== undefined) {
    if (!/^\d{4,12}$/.test(args.pin)) throw new Error('The PIN must be 4 to 12 digits.');
    return { pin: args.pin, lanPin: args.lanPin !== undefined ? args.lanPin : true };
  }
  if (!interactive) {
    return { pin: settings.pin, lanPin: args.lanPin !== undefined ? args.lanPin : settings.lanPin !== false };
  }

  if (mode === 'lan') {
    for (;;) {
      const answer = await ask(`\n  PIN for the local link ${c.dim('(4-12 digits, Enter = no PIN)')}: `);
      if (!answer) return { pin: settings.pin, lanPin: false };
      if (/^\d{4,12}$/.test(answer)) return { pin: answer, lanPin: true };
      log(`  ${sym.warn} ${c.yellow('Digits only, 4 to 12 of them.')}`);
    }
  }

  let pin = settings.pin;
  for (;;) {
    const answer = await ask(`\n  PIN visitors must type ${c.dim(`(4-12 digits, Enter = ${settings.pin})`)}: `);
    if (!answer) break;
    if (/^\d{4,12}$/.test(answer)) { pin = answer; break; }
    log(`  ${sym.warn} ${c.yellow('Digits only, 4 to 12 of them.')}`);
  }
  if (mode === 'cloud') return { pin, lanPin: true };

  const answer = await ask(`  Ask for the PIN on the local link too? ${c.dim(settings.lanPin === false ? '[y/N]' : '[Y/n]')}: `);
  const lanPin = answer ? /^y/i.test(answer) : settings.lanPin !== false;
  return { pin, lanPin };
}

async function ensureCloudflared(interactive) {
  let bin = findCloudflared();
  if (bin) return bin;

  log(`\n  ${c.yellow('cloudflared is not installed.')} It's Cloudflare's official tunnel program.`);
  if (process.platform === 'win32' && interactive) {
    const answer = await ask(`  Install it now with ${c.bold('winget install --id Cloudflare.cloudflared')}? [Y/n]: `);
    if (!/^n/i.test(answer)) {
      closeMenu();
      await new Promise((resolve) => {
        const child = spawn('winget', ['install', '--id', 'Cloudflare.cloudflared', '-e'], { stdio: 'inherit' });
        child.on('exit', resolve);
        child.on('error', resolve);
      });
      bin = findCloudflared();
      if (bin) return bin;
    }
  }
  log('  Install it, then run Share again:');
  log(`    Windows:  ${c.bold('winget install --id Cloudflare.cloudflared')}`);
  log(`    macOS:    ${c.bold('brew install cloudflared')}`);
  log('    Other:    https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/');
  return null;
}

/* ---------------- one shared app ---------------- */

class AppShare {
  constructor({ target, owner }) {
    this.target = target;
    this.owner = owner;
    this.up = true;
    this.label = appLabel(target);
  }

  get lanPort() { return this.lanActualPort; }

  async start() {
    const owner = this.owner;
    this.up = await isUp(this.target.host, this.target.port);

    if (owner.wantsLan) {
      this.gate = new PinGate({
        pin: owner.pin,
        enabled: owner.lanPin,
        secret: owner.settings.lanSecret,
        onUnlock: ({ ip, ua }) => owner.note(`${deviceName(ua)} (${ip}) unlocked ${this.label} on the local link.`),
        onLockout: ({ ip }) => owner.warn(`Blocked ${ip} for 10 minutes after too many wrong PINs.`),
      });
      this.server = createShareServer({ target: this.target, gate: this.gate, onEvent: () => this.check() });
      this.lanActualPort = await this.server.listen('0.0.0.0', owner.lanPortFor(this.target.port), 20);
    }

    if (owner.wantsCloud) {
      this.e2e = new E2EShare({
        target: this.target,
        pin: owner.pin,
        onUnlock: ({ ip, ua }) => owner.note(`${deviceName(ua)} (${ip}) unlocked ${this.label} on the internet link.`),
        onLockout: ({ ip }) => owner.warn(`Blocked ${ip} for 10 minutes after too many wrong PINs.`),
      });
      // Internal-only listener: reachable from this PC (cloudflared) but never from the network
      const port = await this.e2e.listen('127.0.0.1', 0);
      this.tunnel = new QuickTunnel({ bin: owner.cloudflared, localPort: port });
      this.tunnel.on('status', () => owner.onTunnelStatus(this));
      this.tunnel.start();
    }
  }

  lanLink() {
    if (!this.server) return null;
    const host = this.owner.mdns && this.owner.mdns.ok ? this.owner.mdns.host : this.owner.watcher.current.primary;
    return host ? `http://${host}:${this.lanActualPort}` : null;
  }

  cloudLink() {
    if (!this.tunnel || !this.tunnel.url) return null;
    return `${this.tunnel.url}/#${this.e2e.linkFragment}`;
  }

  links() {
    return [
      { id: 'local', label: 'local network', link: this.lanLink(), file: `${slug(this.label)}-local.png` },
      { id: 'internet', label: 'internet', link: this.cloudLink(), file: `${slug(this.label)}-internet.png` },
    ].filter((entry) => entry.link);
  }

  // Wait until the tunnel has a link, so the window can print everything in one go
  waitForTunnel(timeoutMs = 60000) {
    if (!this.tunnel || this.cloudLink()) return Promise.resolve();
    return new Promise((resolve) => {
      const finish = () => { clearTimeout(timer); this.tunnel.off('status', check); resolve(); };
      const check = () => { if (this.cloudLink()) finish(); };
      const timer = setTimeout(finish, timeoutMs);
      this.tunnel.on('status', check);
      check();
    });
  }

  setPin(pin, lanPin) {
    if (this.gate) {
      this.gate.setPin(pin);
      this.gate.enabled = lanPin;
      this.server.kickAll();
    }
    if (this.e2e) this.e2e.setPin(pin);
  }

  async check() {
    const up = await isUp(this.target.host, this.target.port);
    if (up === this.up) return;
    this.up = up;
    if (up) this.owner.note(`${this.label} is running again.`, 'ok');
    else this.owner.warn(`${this.label} (port ${this.target.port}) isn't responding. Visitors see a "waiting" page until it's back.`);
  }

  async render() {
    const owner = this.owner;
    const where = `http://${this.target.host.includes(':') ? `[${this.target.host}]` : this.target.host}:${this.target.port}`;
    log(`\n  ${c.bold(this.label.toUpperCase())}  ${c.dim(`-> ${where}`)}  ${this.up ? c.green('● running') : c.yellow('● not responding yet')}`);

    if (this.server) {
      const link = this.lanLink();
      if (!link) {
        log(`  ${sym.off} ${c.yellow('Local network: not connected to a network yet.')}`);
      } else {
        log(`  ${c.dim('local')}     ${c.bold(c.cyan(link))}  ${c.dim(owner.lanPin ? '· PIN' : '· no PIN')}`);
        if (this.lanActualPort !== owner.lanPortFor(this.target.port)) {
          log(`  ${sym.warn} ${c.yellow(`Preferred port was busy, using ${this.lanActualPort} for now.`)}`);
        }
      }
    }
    if (this.tunnel && !this.cloudLink()) {
      log(`  ${c.dim('internet')}  ${c.dim(this.tunnel.status === 'reconnecting' ? 'reconnecting...' : 'still starting - the link appears below as soon as it is ready')}`);
    }

    const local = this.links().find((entry) => entry.id === 'local');
    if (local) {
      log('');
      if (this.cloudLink()) log(c.dim('    local network'));
      log(indent(await qr.terminal(local.link)));
    }
    if (this.cloudLink()) await this.renderInternet();
  }

  // Printed on its own when the tunnel comes up (or comes back) after the first screen
  async renderInternet() {
    const link = this.cloudLink();
    if (!link) return;
    log(`\n  ${c.dim('internet')}  ${c.bold(c.cyan(link))}  ${c.dim('· encrypted end-to-end · PIN')}`);
    log('');
    if (this.lanLink()) log(c.dim('    internet'));
    log(indent(await qr.terminal(link)));
  }

  stop() {
    if (this.tunnel) this.tunnel.stop();
    if (this.server) this.server.close();
    if (this.e2e) this.e2e.close();
  }
}

/* ---------------- the running app ---------------- */

class ShareApp {
  constructor({ settings, target, mode, pin, lanPin, cloudflared }) {
    Object.assign(this, { settings, mode, pin, lanPin, cloudflared });
    this.share = new AppShare({ target, owner: this });
    this.publicProfile = false;
    this.pendingKey = null;
    this.busy = false;
  }

  get wantsLan() { return this.mode === 'lan' || this.mode === 'both'; }
  get wantsCloud() { return (this.mode === 'cloud' || this.mode === 'both') && !!this.cloudflared; }
  get usesPin() { return this.wantsCloud || this.lanPin; }

  note(text, kind = 'info') {
    log(`\n  ${kind === 'ok' ? sym.ok : sym.info} ${kind === 'ok' ? c.green(text) : text}`);
  }

  warn(text) {
    log(`\n  ${sym.warn} ${c.yellow(text)}`);
  }

  // Each app keeps the same local port between runs
  lanPortFor(targetPort) {
    const map = this.settings.lanPorts || (this.settings.lanPorts = {});
    if (map[targetPort]) return map[targetPort];
    const used = new Set(Object.values(map));
    let port = this.settings.lanPort;
    while (used.has(port)) port += 1;
    map[targetPort] = port;
    config.save(this.settings);
    return port;
  }

  links() {
    return this.share.links();
  }

  async start() {
    this.watcher = new NetworkWatcher(3000);
    await this.watcher.start();
    if (this.wantsLan) this.mdns = startMdns(this.settings.lanWords, this.watcher, (msg) => log(c.dim(`  ${msg}`)));

    await this.share.start();

    this.watcher.on('change', (snap, prev) => this.onNetworkChange(snap, prev));
    this.healthTimer = setInterval(() => this.share.check(), 5000);
    await this.checkFirewallProfile(true);

    for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(signal, () => this.shutdown());
    process.on('exit', () => { if (this.share.tunnel && this.share.tunnel.child) this.share.tunnel.child.kill(); });
    process.on('uncaughtException', (err) => {
      log(c.red(`\n  Unexpected error: ${err.stack || err.message}`));
      this.shutdown(1);
    });

    this.startedAt = Date.now();
    // Print one finished screen instead of a half-empty one that gets redrawn
    if (this.wantsCloud) {
      log(c.dim('\n  Starting the encrypted tunnel, a few seconds...'));
      await this.share.waitForTunnel(60000);
    }
    await this.render(true);
    this.setupKeys();
  }

  /* ----- background events ----- */

  onTunnelStatus(share) {
    const tunnel = share.tunnel;
    if (tunnel.status === 'live' && tunnel.url !== share.printedUrl) {
      share.printedUrl = tunnel.url;
      share.printedVerified = false;
      if (this.started) { // came up (or came back) after the screen was drawn: add just this part
        share.renderInternet().then(() => this.printKeys()).catch(() => {});
      }
    } else if (tunnel.status === 'live' && tunnel.verified && !share.printedVerified) {
      share.printedVerified = true;
      log(`  ${sym.ok} ${c.green('Internet link checked: it opens from outside.')}`);
    } else if (tunnel.status === 'reconnecting' && share.printedStatus !== 'reconnecting') {
      this.warn(tunnel.error || `${share.label}: tunnel dropped, reconnecting...`);
      log(c.dim('    A new internet link + QR code will be printed when it is back.'));
    }
    share.printedStatus = tunnel.status;
  }

  async onNetworkChange(snap, prev) {
    if (this.mdns) this.mdns.announce();
    await this.checkFirewallProfile();
    if (!this.wantsLan || snap.primary === prev.primary) return;
    const stable = this.mdns && this.mdns.ok;
    this.note(c.dim(`This PC's IP changed: ${prev.primary || 'offline'} -> ${snap.primary || 'offline'}.`)
      + (stable ? c.dim(' Your links and QR codes stay the same.') : ''));
    if (!stable && snap.primary) await this.render(false);
  }

  checkFirewallProfile(quiet = false) {
    if (process.platform !== 'win32' || !this.wantsLan) return Promise.resolve();
    const command = "(Get-NetConnectionProfile | Where-Object { $_.IPv4Connectivity -ne 'Disconnected' } | ForEach-Object { $_.NetworkCategory }) -join ','";
    return new Promise((resolve) => {
      execFile('powershell', ['-NoProfile', '-NonInteractive', '-Command', command], { windowsHide: true, timeout: 10000 }, (err, out) => {
        const isPublic = !err && /Public/i.test(String(out));
        const changed = isPublic !== this.publicProfile;
        this.publicProfile = isPublic;
        if (changed && isPublic && !quiet) this.printFirewallWarning();
        resolve();
      });
    });
  }

  printFirewallWarning() {
    log(`\n  ${sym.warn} ${c.yellow('Windows marks this Wi-Fi as a "Public" network, so the firewall may block your phone.')}`);
    log(c.dim('    If a local link does not open: Settings > Network & internet > Wi-Fi > your network > "Private network",'));
    log(c.dim('    and click "Allow" if Windows Firewall asks about Node.js.'));
  }

  /* ----- hotkeys ----- */

  async copyLink() {
    const list = this.links();
    if (!list.length) return log(`\n  ${sym.info} No link yet, try again in a moment.`);
    let choice = list[0];
    if (list.length > 1) {
      log(`\n  Which link do you want to copy?`);
      list.forEach((entry, i) => log(`   ${c.cyan(String(i + 1))}  ${entry.label}`));
      const answer = await this.readKey(`  Press 1-${Math.min(list.length, 9)} (anything else cancels): `);
      choice = list[Number(answer) - 1];
      if (!choice) return;
    }
    if (await copyToClipboard(choice.link)) log(`  ${sym.ok} ${c.green('Copied:')} ${choice.link}`);
    else log(`  ${sym.warn} Could not copy. Select the link above with the mouse instead.`);
  }

  async saveQrImages() {
    const list = this.links();
    if (!list.length) return log(`\n  ${sym.info} No link yet, try again in a moment.`);
    const dir = path.join(__dirname, 'qr-codes');
    fs.mkdirSync(dir, { recursive: true });
    log('');
    for (const entry of list) {
      const file = path.join(dir, entry.file);
      fs.writeFileSync(file, await qr.png(entry.link));
      log(`  ${sym.ok} ${entry.label.padEnd(30)} ${c.cyan(file)}`);
    }
    if (this.usesPin) log(c.dim(`    The PIN (${this.pin}) is not in the image: tell people the PIN separately.`));
    if (this.wantsCloud) log(c.dim('    Internet links change every time Share starts, so save those images again next time.'));
  }

  async changePin() {
    const canRemove = !this.wantsCloud; // the internet link always needs a PIN
    const verb = this.usesPin ? 'New PIN' : 'PIN';
    const pin = await this.prompt(`\n  ${verb} ${c.dim(canRemove && this.lanPin ? '(4-12 digits, Enter = remove the PIN)' : '(4-12 digits, Enter = cancel)')}: `);

    if (!pin) {
      if (!canRemove || !this.lanPin) return log(c.dim('  Cancelled.'));
      this.lanPin = false;
      this.settings.lanPin = false;
      config.save(this.settings);
      this.share.setPin(this.pin, false);
      log(`  ${sym.ok} PIN removed. Anyone on your Wi-Fi can open the local links now.`);
      return this.printKeys();
    }
    if (!/^\d{4,12}$/.test(pin)) return log(`  ${sym.warn} ${c.yellow('Digits only, 4 to 12 of them.')}`);

    const added = !this.lanPin && !this.wantsCloud;
    this.pin = pin;
    this.lanPin = true;
    this.settings.pin = pin;
    this.settings.lanPin = true;
    config.save(this.settings);
    this.share.setPin(pin, true);
    log(`  ${sym.ok} ${c.green(`PIN is now ${pin}.`)} ${added ? 'The local links ask for it from now on.' : 'Everyone has to unlock again.'}`);
    this.printKeys();
  }

  /* ----- output ----- */

  async render(clear = false) {
    if (clear && process.stdout.isTTY) console.clear();
    log('');
    rule();
    log(`  ${c.bold('SHARE')}  ${this.share.label}  ${c.dim(this.mode === 'lan' ? '· local network' : this.mode === 'cloud' ? '· internet' : '· local network + internet')}`);
    rule();
    await this.share.render();
    if (this.publicProfile) this.printFirewallWarning();
    this.printKeys();
  }

  printKeys() {
    const key = (letter, text) => `${c.inverse(` ${letter} `)} ${text}`;
    log('');
    rule();
    if (this.usesPin) {
      const where = this.wantsCloud && !this.lanPin && this.wantsLan ? ' (internet link only)' : '';
      log(`  ${c.bold('PIN')} ${c.bold(c.cyan(this.pin))}${c.dim(where)}  ${c.dim('tell this to people separately from the link')}`);
    } else {
      log(`  ${c.dim('No PIN: anyone on your Wi-Fi can open the local links.')}`);
    }
    log(`  ${key('C', 'copy link')}   ${key('S', 'save QR images')}   ${key('P', this.usesPin ? 'change PIN' : 'add PIN')}   ${key('Q', 'quit')}`);
    log(c.dim('  Another app to share? Open Share again in a new window - it takes the next port by itself.'));
    rule();
  }

  /* ----- keyboard ----- */

  setupKeys() {
    if (!process.stdin.isTTY) return;
    readline.emitKeypressEvents(process.stdin);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    this.onKey = (str, key) => this.handleKey(str, key || {});
    process.stdin.on('keypress', this.onKey);
  }

  async handleKey(str, key) {
    if (key.ctrl && key.name === 'c') return this.shutdown();
    const name = String(key.name || str || '').toLowerCase();

    if (this.pendingKey) { // answering a one-key question
      const resolve = this.pendingKey;
      this.pendingKey = null;
      return resolve(name);
    }
    if (this.busy) return;
    this.busy = true;
    try {
      switch (name) {
        case 'q': return this.shutdown();
        case 'c': await this.copyLink(); break;
        case 's': await this.saveQrImages(); break;
        case 'p': await this.changePin(); break;
        case 'return': case 'enter': await this.render(true); break;
        default:
      }
    } catch (err) {
      log(c.red(`  ${err.message}`));
    } finally {
      this.busy = false;
    }
  }

  readKey(question) {
    process.stdout.write(question);
    return new Promise((resolve) => {
      this.pendingKey = (name) => {
        process.stdout.write(`${name === 'return' ? '' : name}\n`);
        resolve(name);
      };
    });
  }

  // Typed answer (e.g. a new PIN) while the hotkeys are paused
  async prompt(question) {
    process.stdin.off('keypress', this.onKey);
    process.stdin.setRawMode(false);
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.on('SIGINT', () => this.shutdown());
    const answer = await new Promise((resolve) => rl.question(question, resolve));
    rl.close();
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('keypress', this.onKey);
    return String(answer).trim();
  }

  shutdown(code = 0) {
    if (this.stopping) return;
    this.stopping = true;
    log(c.dim('\n  Stopping... all links are closed now.'));
    try { if (process.stdin.isTTY) process.stdin.setRawMode(false); } catch {}
    clearInterval(this.healthTimer);
    this.share.stop();
    if (this.mdns) this.mdns.stop();
    if (this.watcher) this.watcher.stop();
    setTimeout(() => process.exit(code), 400);
  }
}

/* ---------------- main ---------------- */

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) return printHelp();

  const interactive = !!(process.stdin.isTTY && process.stdout.isTTY);
  const settings = config.load();

  log(`\n  ${c.bold('SHARE')} ${c.dim('- share a localhost app on your network or the internet')}\n`);

  const target = await pickTarget(args, settings, interactive);
  if (!(target.port > 0 && target.port < 65536)) throw new Error(`${target.port} is not a valid port number.`);

  const mode = args.mode || (interactive ? await pickMode(settings) : settings.lastMode || 'lan');
  let cloudflared = null;
  if (mode !== 'lan') {
    cloudflared = await ensureCloudflared(interactive);
    if (!cloudflared && mode === 'cloud') process.exit(1);
  }

  const { pin, lanPin } = await askPin(settings, args, mode, interactive);
  closeMenu();

  settings.targetPort = target.port;
  settings.lastMode = mode;
  settings.pin = pin;
  settings.lanPin = lanPin;
  if (args.lanPort) settings.lanPort = args.lanPort;
  config.save(settings);

  const app = new ShareApp({ settings, target, mode, pin, lanPin, cloudflared });
  await app.start();
}

main().catch((err) => {
  log(c.red(`\n  x ${err.message}`));
  process.exit(1);
});
