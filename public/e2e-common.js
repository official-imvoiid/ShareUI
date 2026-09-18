// Shared by the unlock page, the service worker and the page helper.
// Wire format must match lib/e2e.js exactly.
var E2E = (function () {
  var te = new TextEncoder();
  var td = new TextDecoder();
  var MAX_FRAME = 4 * 1024 * 1024;

  function concat() {
    var total = 0;
    for (var i = 0; i < arguments.length; i++) total += arguments[i].length;
    var out = new Uint8Array(total);
    var at = 0;
    for (var j = 0; j < arguments.length; j++) { out.set(arguments[j], at); at += arguments[j].length; }
    return out;
  }

  function b64(u8) {
    var s = '';
    for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function unb64(s) {
    var norm = String(s).replace(/-/g, '+').replace(/_/g, '/');
    var bin = atob(norm + '==='.slice((norm.length + 3) % 4));
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function u32(n) { var b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; }
  function u64(n) { var b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; }
  function rand(n) { return crypto.getRandomValues(new Uint8Array(n)); }
  function label(name) { return te.encode('share-e2e/1 ' + name); }

  async function hmac(keyBytes, data) {
    var key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
  }

  function sameBytes(a, b) {
    if (a.length !== b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  // secret (from the #link) + PIN -> 32-byte master key; the PIN never leaves the device
  async function masterKey(secret, pin, salt, iterations) {
    var base = await crypto.subtle.importKey('raw', concat(secret, te.encode(pin)), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iterations }, base, 256));
  }

  // One encrypted frame: [u32 length][12-byte IV][AES-GCM(flags byte + data)]
  async function seal(key, flags, data, aad) {
    var iv = rand(12);
    var ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad }, key, concat(new Uint8Array([flags]), data)));
    return concat(u32(12 + ct.length), iv, ct);
  }

  async function open(key, frame, aad) {
    var pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: frame.subarray(0, 12), additionalData: aad }, key, frame.subarray(12)));
    return { flags: pt[0], data: pt.subarray(1) };
  }

  function frameReader(stream) {
    var reader = stream.getReader();
    var buf = new Uint8Array(0);
    return {
      next: async function () {
        for (;;) {
          if (buf.length >= 4) {
            var len = new DataView(buf.buffer, buf.byteOffset, 4).getUint32(0);
            if (len < 13 || len > MAX_FRAME) throw new Error('Bad frame');
            if (buf.length >= 4 + len) {
              var frame = buf.slice(4, 4 + len);
              buf = buf.slice(4 + len);
              return frame;
            }
          }
          var r = await reader.read();
          if (r.done) {
            if (buf.length) throw new Error('Connection cut in the middle of a frame');
            return null;
          }
          buf = buf.length ? concat(buf, r.value) : r.value;
        }
      },
      cancel: function () { reader.cancel().catch(function () {}); },
    };
  }

  function aad(kind, sidBytes, idBytes, index) {
    return concat(label(kind), sidBytes, idBytes, u32(index));
  }

  function wsAad(sidBytes, connId, dir, seq) {
    return concat(label('ws'), sidBytes, connId, new Uint8Array([dir]), u32(seq));
  }

  // Tiny IndexedDB key/value store (CryptoKey objects can be stored without ever being exportable)
  var dbPromise = null;
  function db() {
    if (!dbPromise) {
      dbPromise = new Promise(function (resolve, reject) {
        var req = indexedDB.open('share-e2e', 1);
        req.onupgradeneeded = function () { req.result.createObjectStore('kv'); };
        req.onsuccess = function () { resolve(req.result); };
        req.onerror = function () { dbPromise = null; reject(req.error); };
      });
    }
    return dbPromise;
  }
  function kv(mode, fn) {
    return db().then(function (d) {
      return new Promise(function (resolve, reject) {
        var tx = d.transaction('kv', mode);
        var req = fn(tx.objectStore('kv'));
        tx.oncomplete = function () { resolve(req && req.result); };
        tx.onerror = function () { reject(tx.error); };
      });
    });
  }
  function get(k) { return kv('readonly', function (s) { return s.get(k); }); }
  function set(k, v) { return kv('readwrite', function (s) { return s.put(v, k); }); }
  function del(k) { return kv('readwrite', function (s) { return s.delete(k); }); }

  return {
    te: te, td: td, concat: concat, b64: b64, unb64: unb64, u32: u32, u64: u64, rand: rand, label: label,
    hmac: hmac, sameBytes: sameBytes, masterKey: masterKey, seal: seal, open: open, frameReader: frameReader,
    aad: aad, wsAad: wsAad, get: get, set: set, del: del,
  };
})();
