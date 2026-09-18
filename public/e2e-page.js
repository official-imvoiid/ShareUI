// Injected into every page of your app when it is opened through the internet link.
// Service workers cannot see WebSockets, so this replaces WebSocket with an encrypted one,
// and copies app cookies the page's own JavaScript needs to read.
/* global E2E */
(function () {
  if (window.__shareE2E) return;
  window.__shareE2E = true;
  try { sessionStorage.removeItem('share-reloaded'); } catch (e) { /* ignore */ }

  var NativeWebSocket = window.WebSocket;
  var sessionPromise = null;
  function session() {
    if (!sessionPromise) {
      sessionPromise = E2E.get('session').then(function (s) {
        if (!s) throw new Error('This link is locked again. Reload the page.');
        return { sid: s.sid, sidBytes: E2E.unb64(s.sid), key: s.key };
      });
    }
    return sessionPromise;
  }

  /* ---------- cookies the app's JavaScript reads ---------- */

  function applyCookies(list) {
    (list || []).forEach(function (cookie) {
      try {
        document.cookie = cookie[0] + '=' + cookie[1] + '; path=/' + (cookie[2] ? '; max-age=0' : '');
      } catch (e) { /* ignore */ }
    });
  }
  if (navigator.serviceWorker) {
    navigator.serviceWorker.addEventListener('message', function (event) {
      if (event.data && event.data.type === 'share-cookies') applyCookies(event.data.cookies);
    });
  }
  fetch('/__e2e_jar', { cache: 'no-store' })
    .then(function (r) { return r.ok ? r.json() : []; })
    .then(applyCookies)
    .catch(function () { /* no cookies yet */ });

  /* ---------- encrypted WebSocket ---------- */

  if (!NativeWebSocket) return;

  class ShareWebSocket extends EventTarget {
    constructor(url, protocols) {
      var target = null;
      try { target = new URL(url, location.href); } catch (e) { /* let the native one complain */ }
      if (!target || target.host !== location.host) {
        return protocols === undefined ? new NativeWebSocket(url) : new NativeWebSocket(url, protocols);
      }
      super();
      this.url = target.href.replace(/^http/, 'ws');
      this.readyState = 0;
      this.protocol = '';
      this.extensions = '';
      this.bufferedAmount = 0;
      this.binaryType = 'blob';
      this.onopen = null;
      this.onmessage = null;
      this.onerror = null;
      this.onclose = null;

      this._tx = Promise.resolve();
      this._rx = Promise.resolve();
      this._seqOut = 0;
      this._seqIn = 0;
      this._closeInfo = null;
      this._byUser = false;

      var list = protocols === undefined ? [] : (Array.isArray(protocols) ? protocols : [protocols]);
      this._start(target.pathname + target.search, list.map(String));
    }
  }

  ShareWebSocket.prototype._fire = function (type, event) {
    var handler = this['on' + type];
    if (typeof handler === 'function') {
      try { handler.call(this, event); } catch (err) { setTimeout(function () { throw err; }); }
    }
    this.dispatchEvent(event);
  };

  ShareWebSocket.prototype._start = async function (path, protocols) {
    try {
      var s = await session();
      if (this.readyState >= 2) return this._finish(1006, '', false);
      this._session = s;
      this._conn = E2E.rand(16);
      var scheme = location.protocol === 'https:' ? 'wss://' : 'ws://';
      var socket = new NativeWebSocket(scheme + location.host + '/__e2e/ws?s=' + encodeURIComponent(s.sid) + '&c=' + encodeURIComponent(E2E.b64(this._conn)));
      socket.binaryType = 'arraybuffer';
      this._socket = socket;
      var self = this;
      socket.onopen = function () {
        self._send(0, E2E.te.encode(JSON.stringify({ t: Date.now(), p: path, pr: protocols })));
      };
      socket.onmessage = function (event) {
        var data = new Uint8Array(event.data);
        self._rx = self._rx.then(function () { return self._receive(data); });
      };
      socket.onclose = function () {
        self._rx = self._rx.then(function () {
          var info = self._closeInfo;
          self._finish(info ? info.code : 1006, info ? info.reason : '', !!info);
        });
      };
      socket.onerror = function () { /* close follows */ };
    } catch (err) {
      this._finish(1006, '', false);
    }
  };

  ShareWebSocket.prototype._send = function (kind, payload) {
    var self = this;
    var seq = this._seqOut++;
    this._tx = this._tx.then(async function () {
      var bytes = payload && typeof payload.then === 'function' ? await payload : payload;
      var frame = await E2E.seal(self._session.key, kind, bytes, E2E.wsAad(self._session.sidBytes, self._conn, 0, seq));
      if (self._socket && self._socket.readyState === 1) self._socket.send(frame.subarray(4)); // no length prefix on WS
    }).catch(function () { /* socket went away */ });
  };

  ShareWebSocket.prototype._receive = async function (data) {
    var part;
    try {
      part = await E2E.open(this._session.key, data, E2E.wsAad(this._session.sidBytes, this._conn, 1, this._seqIn++));
    } catch (err) {
      this._closeInfo = { code: 1006, reason: 'bad frame' };
      if (this._socket) this._socket.close();
      return;
    }
    if (part.flags === 0) { // control
      var control = JSON.parse(E2E.td.decode(part.data));
      if (control.type === 'open' && this.readyState === 0) {
        this.protocol = control.protocol || '';
        this.readyState = 1;
        this._fire('open', new Event('open'));
      }
      return;
    }
    if (part.flags === 3) {
      var info = JSON.parse(E2E.td.decode(part.data));
      this._closeInfo = { code: info.code || 1005, reason: info.reason || '' };
      if (this._socket) this._socket.close();
      return;
    }
    if (part.flags === 4) return; // keep-alive
    if (this.readyState !== 1) return;
    var payload = part.flags === 1
      ? E2E.td.decode(part.data)
      : (this.binaryType === 'arraybuffer' ? part.data.slice().buffer : new Blob([part.data]));
    this._fire('message', new MessageEvent('message', { data: payload, origin: location.origin }));
  };

  ShareWebSocket.prototype._finish = function (code, reason, clean) {
    if (this.readyState === 3) return;
    this.readyState = 3;
    if (!clean && !this._byUser) this._fire('error', new Event('error'));
    this._fire('close', new CloseEvent('close', { code: code, reason: reason, wasClean: clean }));
  };

  ShareWebSocket.prototype.send = function (data) {
    if (this.readyState === 0) {
      throw new DOMException("Failed to execute 'send' on 'WebSocket': Still in CONNECTING state.", 'InvalidStateError');
    }
    if (this.readyState !== 1) return;
    if (typeof data === 'string') return this._send(1, E2E.te.encode(data));
    if (typeof Blob !== 'undefined' && data instanceof Blob) {
      return this._send(2, data.arrayBuffer().then(function (buf) { return new Uint8Array(buf); }));
    }
    if (data instanceof ArrayBuffer) return this._send(2, new Uint8Array(data.slice(0)));
    if (ArrayBuffer.isView(data)) return this._send(2, new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength)));
    return this._send(1, E2E.te.encode(String(data)));
  };

  ShareWebSocket.prototype.close = function (code, reason) {
    if (this.readyState >= 2) return;
    var connecting = this.readyState === 0;
    this._byUser = true;
    this.readyState = 2;
    this._closeInfo = { code: code || 1005, reason: reason || '' };
    var self = this;
    if (this._socket && !connecting) {
      this._send(3, E2E.te.encode(JSON.stringify({ code: code || 1000, reason: reason || '' })));
      this._tx = this._tx.then(function () { self._socket.close(); });
    } else if (this._socket) {
      this._socket.close();
    } else {
      setTimeout(function () { self._finish(code || 1005, reason || '', true); });
    }
  };

  ShareWebSocket.CONNECTING = ShareWebSocket.prototype.CONNECTING = 0;
  ShareWebSocket.OPEN = ShareWebSocket.prototype.OPEN = 1;
  ShareWebSocket.CLOSING = ShareWebSocket.prototype.CLOSING = 2;
  ShareWebSocket.CLOSED = ShareWebSocket.prototype.CLOSED = 3;

  window.WebSocket = ShareWebSocket;
})();
