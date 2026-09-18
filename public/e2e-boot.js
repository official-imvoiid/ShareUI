// Unlock page logic: turns the link secret + your PIN into an encryption key, proves it to the owner's PC,
// then installs the service worker that encrypts everything from here on.
/* global E2E */
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var CFG = JSON.parse($('cfg').textContent);
  var secret = null;

  var VIEWS = { busy: 'busy', pin: 'pinForm', nolink: 'nolink', unsupported: 'unsupported' };

  function show(view, message) {
    Object.keys(VIEWS).forEach(function (name) { $(VIEWS[name]).hidden = name !== view; });
    $('err').textContent = message || '';
    if (view === 'pin') { $('pinInput').value = ''; $('pinInput').focus(); }
  }

  function busy(text) {
    show('busy');
    $('busyText').textContent = text;
  }

  async function start() {
    if (!window.isSecureContext || !('serviceWorker' in navigator) || !window.crypto || !crypto.subtle || !window.indexedDB) {
      return show('unsupported');
    }
    try {
      var fromLink = new URLSearchParams(location.hash.slice(1)).get('k');
      if (location.hash) history.replaceState(null, '', location.pathname + location.search);
      if (fromLink) {
        secret = E2E.unb64(fromLink);
        await E2E.set('secret', secret);
        await E2E.del('session'); // a freshly opened link always asks for the PIN again
      } else {
        secret = await E2E.get('secret');
      }
      if (!secret) return show('nolink');

      // A hard refresh skips the service worker; if we are still unlocked just load again normally
      var open = await E2E.get('session');
      var registration = await navigator.serviceWorker.getRegistration('/');
      if (open && registration && registration.active && !navigator.serviceWorker.controller && !sessionStorage.getItem('share-reloaded')) {
        sessionStorage.setItem('share-reloaded', '1');
        location.reload();
        return;
      }
      show('pin');
    } catch (err) {
      show('pin', 'Could not start: ' + err.message);
    }
  }

  async function unlock(pin) {
    busy('Checking PIN…');
    try {
      var key = await E2E.masterKey(secret, pin, E2E.unb64(CFG.salt), CFG.iterations);
      var nonce = E2E.rand(32);
      var time = Date.now();
      var proof = await E2E.hmac(key, E2E.concat(E2E.label('hello'), nonce, E2E.u64(time)));

      var res = await fetch('/__e2e/hello', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        credentials: 'omit',
        cache: 'no-store',
        body: JSON.stringify({ nc: E2E.b64(nonce), t: time, mac: E2E.b64(proof) }),
      });
      var body = await res.json().catch(function () { return {}; });
      if (!res.ok) return show('pin', body.error || ('Could not unlock (' + res.status + ').'));

      // Check the reply really came from the owner's PC, not from anything in between
      var serverNonce = E2E.unb64(body.ns);
      var sidBytes = E2E.unb64(body.sid);
      var expected = await E2E.hmac(key, E2E.concat(E2E.label('welcome'), nonce, serverNonce, sidBytes));
      if (!E2E.sameBytes(expected, E2E.unb64(body.mac))) {
        return show('pin', 'Security check failed: the answer did not come from the owner\'s PC. Do not continue.');
      }

      var sessionKeyBytes = await E2E.hmac(key, E2E.concat(E2E.label('session'), nonce, serverNonce));
      var sessionKey = await crypto.subtle.importKey('raw', sessionKeyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
      await E2E.set('session', { sid: body.sid, key: sessionKey, created: Date.now() });

      busy('Starting encrypted connection…');
      await navigator.serviceWorker.register('/__e2e/sw.js', { scope: '/' });
      var ready = await navigator.serviceWorker.ready;
      if (ready.active) ready.active.postMessage({ type: 'share-session-changed' });
      if (!navigator.serviceWorker.controller) {
        await new Promise(function (resolve) {
          navigator.serviceWorker.addEventListener('controllerchange', resolve, { once: true });
          setTimeout(resolve, 4000);
        });
      }
      try { sessionStorage.removeItem('share-reloaded'); } catch (e) { /* ignore */ }
      location.reload();
    } catch (err) {
      show('pin', 'Could not unlock: ' + err.message);
    }
  }

  $('pinForm').addEventListener('submit', function (event) {
    event.preventDefault();
    var pin = $('pinInput').value.trim();
    if (pin) unlock(pin);
  });

  start();
})();
