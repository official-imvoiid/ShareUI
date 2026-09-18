// Service worker for the internet link. Every request your app makes is encrypted HERE, on the visitor's
// device, travels through Cloudflare as scrambled bytes, and is decrypted only on the owner's PC.
// Cloudflare never sees page content, URLs, headers or cookies.
/* global E2E, PAGE_JS */
var CACHE = 'share-e2e-v1';
var CHUNK = 1024 * 1024;
var NULL_BODY = { 101: true, 204: true, 205: true, 304: true };

self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (event) { event.waitUntil(self.clients.claim()); });

var sessionPromise = null;
function loadSession() {
  if (!sessionPromise) {
    sessionPromise = E2E.get('session').then(function (s) {
      return s ? { sid: s.sid, sidBytes: E2E.unb64(s.sid), key: s.key } : null;
    }).catch(function () { return null; });
  }
  return sessionPromise;
}

self.addEventListener('message', function (event) {
  if (event.data && event.data.type === 'share-session-changed') sessionPromise = null;
});

self.addEventListener('fetch', function (event) {
  var url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return; // other websites (fonts, CDNs) are not ours to touch
  if (url.pathname === '/__e2e/page.js') {
    event.respondWith(new Response(PAGE_JS, { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'no-cache' } }));
    return;
  }
  if (url.pathname.indexOf('/__e2e/') === 0) return; // unlock page, handshake and tunnel go straight to the network
  event.respondWith(handle(event, url));
});

async function handle(event, url) {
  var req = event.request;
  var isPage = req.mode === 'navigate';
  if (isPage) sessionPromise = null;
  var session = await loadSession();
  if (!session) return locked(isPage);
  try {
    return await tunnel(event, req, url, session);
  } catch (err) {
    if (err && err.expired) {
      await E2E.del('session').catch(function () {});
      await caches.delete(CACHE).catch(function () {});
      sessionPromise = null;
      return locked(isPage);
    }
    return new Response('Share could not load this: ' + ((err && err.message) || err), { status: 502, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  }
}

// Never send the real request unencrypted: show the PIN page instead
function locked(isPage) {
  if (isPage) return fetch('/__e2e/boot', { credentials: 'omit', cache: 'no-store' });
  return new Response('Locked', { status: 401 });
}

async function tunnel(event, req, url, session) {
  var id = E2E.rand(16);
  var headers = [];
  req.headers.forEach(function (value, name) { headers.push([name, value]); });
  if (req.referrer && req.referrer !== 'about:client') {
    try {
      var ref = new URL(req.referrer);
      if (ref.origin === self.location.origin) headers.push(['referer', ref.pathname + ref.search]);
    } catch (e) { /* ignore */ }
  }

  // Revalidate cached files instead of downloading them again (the cache lives on the visitor's device)
  var cache = null;
  var cached = null;
  var cacheable = req.method === 'GET' && !req.headers.has('range');
  if (cacheable) {
    cache = await caches.open(CACHE);
    cached = await cache.match(url.href);
    if (cached) {
      var etag = cached.headers.get('etag');
      var modified = cached.headers.get('last-modified');
      if (etag && !req.headers.has('if-none-match')) headers.push(['if-none-match', etag]);
      if (modified && !req.headers.has('if-modified-since')) headers.push(['if-modified-since', modified]);
    }
  }

  var body = null;
  if (req.method !== 'GET' && req.method !== 'HEAD') body = new Uint8Array(await req.arrayBuffer());

  var head = { t: Date.now(), m: req.method, u: url.pathname + url.search, h: headers, bl: body ? body.length : null };
  var parts = Math.ceil((body ? body.length : 0) / CHUNK);
  var pieces = [await E2E.seal(session.key, parts ? 0 : 1, E2E.te.encode(JSON.stringify(head)), E2E.aad('req', session.sidBytes, id, 0))];
  for (var i = 0; i < parts; i++) {
    pieces.push(await E2E.seal(session.key, i === parts - 1 ? 1 : 0, body.subarray(i * CHUNK, (i + 1) * CHUNK), E2E.aad('req', session.sidBytes, id, i + 1)));
  }

  var res = await fetch('/__e2e/tunnel', {
    method: 'POST',
    body: new Blob(pieces),
    headers: { 'content-type': 'application/octet-stream', 'x-e2e-session': session.sid, 'x-e2e-request': E2E.b64(id) },
    credentials: 'omit',
    cache: 'no-store',
    signal: req.signal,
  });
  if (res.status === 401) { var expired = new Error('Session expired'); expired.expired = true; throw expired; }
  if (!res.ok || !res.body) throw new Error('secure tunnel answered ' + res.status);

  var frames = E2E.frameReader(res.body);
  var index = 0;
  async function nextFrame() {
    for (;;) {
      var frame = await frames.next();
      if (!frame) throw new Error('response was cut off');
      var part = await E2E.open(session.key, frame, E2E.aad('res', session.sidBytes, id, index++));
      if (part.flags & 2) continue; // keep-alive
      return part;
    }
  }

  var meta = JSON.parse(E2E.td.decode((await nextFrame()).data));
  if (meta.c && meta.c.length) shareCookies(event, meta.c);

  if (meta.s === 304 && cached) {
    frames.cancel();
    return cached;
  }

  var responseHeaders = new Headers();
  (meta.h || []).forEach(function (pair) {
    try { responseHeaders.append(pair[0], pair[1]); } catch (e) { /* forbidden header */ }
  });

  var stream = null;
  if (NULL_BODY[meta.s] || req.method === 'HEAD') {
    frames.cancel();
  } else {
    stream = new ReadableStream({
      pull: async function (controller) {
        try {
          for (;;) {
            var part = await nextFrame();
            if (part.data.length) controller.enqueue(part.data.slice());
            if (part.flags & 1) { controller.close(); return; }
            if (part.data.length) return;
          }
        } catch (err) {
          controller.error(err);
        }
      },
      cancel: function () { frames.cancel(); },
    });
    if (meta.z === 'gzip') stream = stream.pipeThrough(new DecompressionStream('gzip'));
    var type = responseHeaders.get('content-type') || '';
    if (/text\/html/i.test(type) && (req.mode === 'navigate' || req.destination === 'iframe' || req.destination === 'document')) {
      stream = stream.pipeThrough(injectHelper());
    }
  }

  var response;
  try {
    response = new Response(stream, { status: meta.s, statusText: meta.st || '', headers: responseHeaders });
  } catch (e) {
    response = new Response(stream, { status: meta.s, headers: responseHeaders });
  }

  if (cacheable && meta.s === 200 && stream && (responseHeaders.has('etag') || responseHeaders.has('last-modified'))
    && !/no-store/i.test(responseHeaders.get('cache-control') || '')) {
    var copy = response.clone();
    event.waitUntil(cache.put(url.href, copy).catch(function () {}));
  }
  return response;
}

// Adds the helper that encrypts WebSockets too, right after <head>
function injectHelper() {
  var tag = E2E.te.encode('<script src="/__e2e/page.js"></script>');
  var latin1 = new TextDecoder('latin1');
  var pending = new Uint8Array(0);
  var done = false;
  return new TransformStream({
    transform: function (chunk, controller) {
      if (done) return controller.enqueue(chunk);
      pending = E2E.concat(pending, chunk);
      var match = /<head[^>]*>/i.exec(latin1.decode(pending));
      if (match || pending.length > 65536) {
        var at = match ? match.index + match[0].length : 0;
        controller.enqueue(pending.subarray(0, at));
        controller.enqueue(tag);
        controller.enqueue(pending.subarray(at));
        pending = null;
        done = true;
      }
    },
    flush: function (controller) {
      if (!done) {
        controller.enqueue(tag);
        controller.enqueue(pending);
      }
    },
  });
}

// Cookies readable by the app's JavaScript are copied into the page (they stay out of network requests)
function shareCookies(event, cookies) {
  var id = event.resultingClientId || event.clientId;
  if (!id) return;
  event.waitUntil(self.clients.get(id).then(function (client) {
    if (client) client.postMessage({ type: 'share-cookies', cookies: cookies });
  }).catch(function () {}));
}
