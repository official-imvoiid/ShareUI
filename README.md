# Share

Share an app running on your PC — ComfyUI, Gradio, text-generation-webui, Streamlit, a Node dev server, anything that speaks HTTP — with a link, a QR code and a PIN. Everything happens in one terminal window: no browser dashboard, no extra ports, no account.

| | Local network | Internet |
|---|---|---|
| Who can open| Devices on your Wi-Fi | Only people with the link **and** the PIN |
| Link | `http://amber-otter-river.local:8000` — the same every time | `https://random-words.trycloudflare.com/#k=…` |
| Encryption | Plain HTTP inside your own network | **End-to-end encrypted** — the relay carries scrambled bytes only |
| PIN | Optional | Required |

```
  ──────────────────────────────────────────────────────────────────
  SHARE  ComfyUI  · local network + internet
  ──────────────────────────────────────────────────────────────────

  COMFYUI  -> http://127.0.0.1:8188  ● running
  local     http://amber-otter-river.local:8000  · PIN
  internet  https://broader-going-segments.trycloudflare.com/#k=…  · encrypted end-to-end · PIN

    █▀▀▀▀▀█ ▀▄█ ▄▀ █▀▀▀▀▀█
    █ ███ █ █▄ ▀█▄ █ ███ █     <- scan it with a phone
    █▄▄▄▄▄█ ▄▀█ ▄▀ █▄▄▄▄▄█

  ──────────────────────────────────────────────────────────────────
  PIN 246813  tell this to people separately from the link
   C  copy link    S  save QR images    P  change PIN    Q  quit
  ──────────────────────────────────────────────────────────────────
```

## Why

Tunnelling services hand your app to whoever finds the URL, and the relay in the middle can read everything passing through it. Share puts a PIN in front of your app and encrypts the traffic **inside the visitor's browser**, so the relay only ever carries ciphertext.

## Requirements

- [Node.js](https://nodejs.org) 18 or newer.
- [cloudflared](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/) — only for the internet option. On Windows, Share offers to install it with `winget`; on macOS use `brew install cloudflared`.
- Visitors need a normal browser (Chrome, Safari, Edge, Firefox). Private windows and browsers built into other apps often block service workers, which the encrypted connection needs.

## Getting started

```bash
git clone https://github.com/official-imvoiid/ShareUI.git
cd ShareUI
npm install
node app.js
```

On Windows you can double-click **`Share.bat`** instead — it installs dependencies on first run.

Then:

1. Pick your app from the list of what is running on this PC (or type a port).
2. Pick **1** local network, **2** internet, or **3** both.
3. Set the PIN — optional on the local network, required for the internet link.

Keys while it runs:

| Key | What it does |
|---|---|
| `C` | Copy a link to the clipboard |
| `S` | Save the QR codes as PNG files into `qr-codes/` |
| `P` | Add or change the PIN (everyone has to unlock again) |
| `Q` | Quit and close every link |

The window also reports when a device unlocks a link, when someone is blocked for wrong PINs, when this PC's IP changes, and when your app stops or comes back.

Skipping the menu:

```bash
node app.js 8188 --lan --no-pin
node app.js 8188 --cloud --pin 246813
node app.js 8188 --both --pin 246813
```

| Option | Meaning |
|---|---|
| `-p, --port <n>` | App port on this PC |
| `--host <addr>` | App address (default `127.0.0.1`) |
| `--lan`, `--cloud`, `--both` | How to share |
| `--lan-port <n>` | First port for local links (default `8000`, remembered per app) |
| `--pin <pin>` | PIN visitors must type (4–12 digits, remembered) |
| `--no-pin` | No PIN on the local link (the internet link always needs one) |

## The local link never changes

The local link is a fixed name like `http://amber-otter-river.local:8000`, chosen once and stored in `share-settings.json`.

Share answers the name lookups for it (mDNS) with whatever IP this PC has at that moment, so when the router hands out a new address, the same link and the same QR code keep working. A background check every 3 seconds keeps it in step.

Works on iPhone, iPad, Mac, Windows, Linux and Android 12+. Older Android phones cannot resolve `.local` names — use the internet link there.

## Sharing a second app

One window shares one app. To share another, open Share again in a second window and pick that app: it takes the next port by itself (`…:8001`), keeps it between runs, and gets its own internet link and PIN. Closing one window only closes that app's links.

## How the internet link is protected

With a plain tunnel the relay terminates your HTTPS and can read every page, request and response — and a free quick tunnel has no password at all, so anyone who learns the URL is inside.

Share works differently:

1. The link carries a random 256-bit secret after `#`. Browsers never send that part over the network, so the relay never receives it.
2. The visitor types the PIN on their own device. Secret + PIN make the encryption key; neither is ever transmitted.
3. A service worker in the visitor's browser encrypts **every** request — URL, headers, cookies and body — with AES-256-GCM. Your PC decrypts it, talks to your app over `127.0.0.1`, and encrypts the answer the same way. WebSockets are encrypted too.
4. Unencrypted requests never reach your app; they only ever get the PIN page.

So the relay sees `POST /__e2e/tunnel` and random bytes. It still sees *that* someone is connected, their IP, and how much data moves — metadata no relay can hide — but not what your app shows or does.

**Verified, not assumed.** A test recorded every byte between `cloudflared` and Share while a real browser used the app through a real tunnel. The recording held only `/__e2e/…` requests with encrypted bodies: no page content, no app URLs, no cookies, no WebSocket messages.

**What it does not protect against.** The PIN page itself is delivered through the relay, so on a visitor's very first visit a hostile relay could in principle serve tampered page code. After that the service worker lives on the device. No browser-only link can do better; a VPN such as Tailscale or WireGuard removes the middleman entirely.

Also built in:

- PIN guesses are rate limited (5 per device and 20 in total per 10 minutes, then a block), and the window tells you when it happens.
- Every encrypted message is bound to its session and numbered, so the relay cannot replay or reorder anything.
- The browser verifies that the answer to the PIN really came from your PC.
- Changing the PIN or quitting logs every device out at once.
- Only the port you picked is reachable; requests aimed at other addresses are refused.
- The internet listener binds to `127.0.0.1`, so that option never opens anything on your Wi-Fi.
- Live output (Gradio queues, ComfyUI progress) streams properly — plain quick tunnels hold event streams back until the response ends.

## Troubleshooting

- **A phone cannot open the local link.** If Windows marks the network as *Public*, the firewall blocks incoming connections: Settings → Network & internet → Wi-Fi → your network → **Private network**, and allow Node.js when Windows Firewall asks. Share warns you when the network is Public.
- **An old Android phone cannot open `.local`.** Use the internet link.
- **`cloudflared` not found.** Let Share install it, or install it yourself (see Requirements).
- **The internet link changes every run.** That is how free quick tunnels work. A permanent address needs a Cloudflare account and your own domain.
- **The app restarted.** Visitors get a "waiting for the app" page that retries by itself.

## Project layout

```
app.js              menu, terminal output, QR codes, hotkeys
lib/e2e.js          end-to-end encrypted tunnel (handshake, requests, WebSockets, cookies)
lib/proxy.js        local network proxy for one port, behind the PIN
lib/gate.js         PIN lock for the local link (rate limits, signed sessions)
lib/tunnel.js       starts cloudflared, restarts it, verifies the link
lib/network.js      LAN IP detection + background change watcher
lib/mdns.js         answers <name>.local with the current IP
lib/ports.js        finds running web apps
lib/words.js        random link names
lib/qr.js           QR codes for the terminal and as PNG
public/e2e-*        unlock page, service worker, page helper, shared crypto
public/gate.html    PIN page for the local link
share-settings.json saved ports, link name and PIN (created on first run, never committed)
```

## License

Project Under MIT — see [LICENSE](LICENSE).
