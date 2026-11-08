// Drm Anti Nui & Anti Backdoor
(function () {
  'use strict';

  const _fetch = window.fetch ? window.fetch.bind(window) : null;
  const _XMLHttpRequest = window.XMLHttpRequest;
  const _Function_toString = Function.prototype.toString;
  const _Date_now = Date.now.bind(Date);
  const _performance_now = (window.performance && window.performance.now)
    ? window.performance.now.bind(window.performance)
    : _Date_now;
  const _setTimeout = window.setTimeout.bind(window);
  const _defineProperty = Object.defineProperty.bind(Object);
  const _JSON_stringify = JSON.stringify.bind(JSON);

  let violationReported = false;

  function getParentRes() {
    return window.GetParentResourceName ? window.GetParentResourceName() : 'drm-scanner';
  }

  function reportViolation(method) {
    if (violationReported) return;
    violationReported = true;

    const payload = _JSON_stringify({
      method: method,
      timestamp: _Date_now()
    });

    try {
      if (_fetch) {
        _fetch(`https://${getParentRes()}/drm:nuiDevToolsDetected`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json; charset=UTF-8' },
          body: payload
        }).catch(function () { });
      }
    } catch (_) { }

    try {
      if (_XMLHttpRequest) {
        const xhr = new _XMLHttpRequest();
        xhr.open('POST', `https://${getParentRes()}/drm:nuiDevToolsDetected`, true);
        xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
        xhr.send(payload);
      }
    } catch (_) { }
  }

  try {
    if (_fetch) {
      _defineProperty(window, 'fetch', { value: _fetch, writable: false, configurable: false });
    }
    if (_XMLHttpRequest) {
      _defineProperty(window, 'XMLHttpRequest', { value: _XMLHttpRequest, writable: false, configurable: false });
    }
  } catch (_) { }

  function isNative(fn) {
    try {
      return typeof fn === 'function' && _Function_toString.call(fn).indexOf('[native code]') !== -1;
    } catch (_) {
      return false;
    }
  }

  // Debounced Debugger Timing: Requires 3 consecutive hits (>250ms) to eliminate game asset hitch false-positives
  let debuggerSpikes = 0;
  function checkDebuggerTiming() {
    try {
      const t0 = _performance_now();
      /* eslint-disable no-debugger */
      debugger;
      const t1 = _performance_now();
      if (t1 - t0 > 250) {
        debuggerSpikes++;
        if (debuggerSpikes >= 3) {
          reportViolation('debugger_timing');
        }
      } else {
        debuggerSpikes = 0;
      }
    } catch (_) { }
  }

  // Master scheduler: Runs every 2500ms via un-clearable microtask chain
  function runMasterProbes() {
    if (violationReported) return;

    try {
      checkDebuggerTiming();

      if (!isNative(window.fetch) || !isNative(Object.defineProperty) || !isNative(Function.prototype.toString)) {
        reportViolation('native_function_hooked');
      }
    } catch (_) { }

    _setTimeout(function () {
      Promise.resolve().then(runMasterProbes);
    }, 2500);
  }

  Promise.resolve().then(runMasterProbes);

  window.addEventListener('keydown', function (e) {
    try {
      const isF12 = e.key === 'F12' || e.keyCode === 123;
      const isInspect = e.ctrlKey && e.shiftKey && (
        e.key === 'I' || e.key === 'i' || e.keyCode === 73 ||
        e.key === 'J' || e.key === 'j' || e.keyCode === 74 ||
        e.key === 'C' || e.key === 'c' || e.keyCode === 67
      );
      const isViewSource = e.ctrlKey && (e.key === 'U' || e.key === 'u' || e.keyCode === 85);

      if (isF12 || isInspect || isViewSource) {
        e.preventDefault();
        e.stopPropagation();
        reportViolation('key_shortcut');
      }
    } catch (_) { }
  }, true);

  // Generate unique CEF Canvas environment entropy
  const _nuiSessionToken = (function () {
    let entropy = 0x5a5a5a5a;
    try {
      const cvs = document.createElement('canvas');
      cvs.width = 16;
      cvs.height = 16;
      const ctx = cvs.getContext('2d');
      if (ctx) {
        ctx.fillStyle = '#223344';
        ctx.fillRect(0, 0, 16, 16);
        ctx.fillStyle = '#ff5500';
        ctx.font = '10px monospace';
        ctx.fillText('CEF', 1, 11);
        const p = ctx.getImageData(0, 0, 16, 16).data;
        for (let i = 0; i < p.length; i += 4) {
          entropy = ((entropy << 5) - entropy) + (p[i] ^ p[i + 1] ^ p[i + 2] ^ p[i + 3]);
          entropy |= 0;
        }
      }
    } catch (_) { }
    return Math.abs(entropy).toString(16) + '_' + Math.random().toString(36).substring(2, 10);
  })();

  function computeSignature(token, salt, seq, sessionToken) {
    let hash = 0;
    const combined = String(token) + ':' + String(salt) + ':' + String(seq) + ':' + String(sessionToken);
    for (let i = 0; i < combined.length; i++) {
      hash = ((hash << 5) - hash) + combined.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(16);
  }

  window.addEventListener('message', function (event) {
    try {
      const data = event.data;
      if (!data) return;

      if (data.action === 'drm:requestNuiReady') {
        notifyNuiReady();
        return;
      }

      if (data.action !== 'drm:challengeHeartbeat') return;
      nuiReadyAcknowledged = true;

      const challengeId = data.challengeId || '';
      const challengeToken = data.token;
      const sessionSalt = data.salt || 'drm_sec_salt';
      const seq = data.seq || 1;
      const sig = computeSignature(challengeToken, sessionSalt, seq, _nuiSessionToken);

      const respPayload = _JSON_stringify({
        challengeId: challengeId,
        token: challengeToken,
        signature: sig,
        seq: seq,
        timestamp: _Date_now()
      });

      if (_fetch) {
        _fetch(`https://${getParentRes()}/drm:nuiHeartbeatResponse`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json; charset=UTF-8' },
          body: respPayload
        }).catch(function () { });
      } else if (_XMLHttpRequest) {
        const xhr = new _XMLHttpRequest();
        xhr.open('POST', `https://${getParentRes()}/drm:nuiHeartbeatResponse`, true);
        xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
        xhr.send(respPayload);
      }
    } catch (_) { }
  });

  let nuiReadyAcknowledged = false;

  function notifyNuiReady() {
    try {
      const payload = _JSON_stringify({ nuiToken: _nuiSessionToken });
      if (_fetch) {
        _fetch(`https://${getParentRes()}/drm:nuiReady`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json; charset=UTF-8' },
          body: payload
        }).then(function () {
          nuiReadyAcknowledged = true;
        }).catch(function () { });
      } else if (_XMLHttpRequest) {
        const xhr = new _XMLHttpRequest();
        xhr.open('POST', `https://${getParentRes()}/drm:nuiReady`, true);
        xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
        xhr.onload = function () { nuiReadyAcknowledged = true; };
        xhr.send(payload);
      }
    } catch (_) { }
  }

  _setTimeout(notifyNuiReady, 500);

  const handshakeInterval = setInterval(function () {
    if (nuiReadyAcknowledged) {
      clearInterval(handshakeInterval);
    } else {
      notifyNuiReady();
    }
  }, 4000);

})();
