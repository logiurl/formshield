/* ══════════════════════════════════════════════════════════════════════════════
   FormShield.js v1.0.0 — Drop-in Form Security Library
   Zero dependencies · Vanilla JS · Web Crypto API
   © 2024 FormShield — MIT License
   ══════════════════════════════════════════════════════════════════════════════

   FEATURES:
     ✓ Input Sanitization   (SQL injection, XSS, path traversal, null bytes)
     ✓ RSA Encryption        (Web Crypto API, OAEP+SHA-256, PHP companion)
     ✓ Bot Detection         (honeypot, timing, behavioral entropy)
     ✓ Rate Limiting         (localStorage, exponential backoff, countdown)
     ✓ Toast Notifications   (custom UI, stacked, progress bar, animated)
     ✓ Security Modals       (injection, bot, lockout, tamper)
     ✓ Form Tamper Detection (MutationObserver, field snapshot)
     ✓ Logging & Reporting   (in-memory, CSV/JSON export, PHP endpoint)

   ══════════════════════════════════════════════════════════════════════════════ */

(function (global, factory) {
  'use strict';
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    global.FormShield = factory();
  }
}(typeof window !== 'undefined' ? window : this, function () {
  'use strict';

  /* ══ SECTION 1: CONFIG & CONSTANTS ══════════════════════════════════════════ */

  var VERSION = '1.0.0';

  var DEFAULTS = {
    // Form Targeting
    formId: null,
    fieldsToEncrypt: ['password'],

    // RSA Encryption
    enableEncryption: true,
    rsaEndpoint: '/get-public-key.php',
    rsaFailMode: 'block',           // 'block' or 'warn'

    // Input Sanitization
    enableSanitization: true,
    sanitizeMode: 'block',          // 'block' or 'strip'
    maxInputLength: 255,
    customBlockPatterns: [],

    // Bot Detection
    enableBotDetection: true,
    botSuspicionThreshold: 60,
    minSubmitTimeMs: 1800,
    honeypotFieldName: 'website',

    // Rate Limiting
    enableRateLimit: true,
    maxAttempts: 5,
    lockoutBaseMinutes: 1,

    // Tamper Detection
    enableTamperDetection: true,
    tamperBlockSubmit: true,

    // Toast Customisation
    toastPosition: 'top-right',
    toastDuration: 4000,
    toastColors: {
      success: '#2ecc71',
      warning: '#f39c12',
      error: '#e74c3c',
      security: '#8e44ad',
      info: '#3498db',
      text: '#ffffff',
      borderRadius: '10px',
      fontSize: '14px'
    },

    // Modal Customisation
    modalColors: {
      overlay: 'rgba(0,0,0,0.7)',
      background: '#1a1a2e',
      title: '#e74c3c',
      text: '#cccccc',
      accent: '#8e44ad',
      border: '#e74c3c',
      buttonPrimary: '#e74c3c',
      buttonSecondary: '#444444'
    },

    // Logging & Reporting
    enableLogging: true,
    reportEndpoint: null,
    reportFormat: 'json',
    reportDirectory: './formshield_logs/',
    reportFilename: 'formshield_log',
    reportFileFormat: 'txt',
    reportOnEvents: ['injection', 'bot', 'lockout', 'tamper', 'rsa_fail', 'rate_limit'],
    reportBatchSize: 1,
    reportAsync: true,

    // Callbacks
    onThreatDetected: null,
    onBotDetected: null,
    onInjectionDetected: null,
    onLockout: null,
    onEncryptionReady: null,
    onSubmitAllowed: null
  };

  // SQL injection patterns
  var SQL_PATTERNS = [
    /('\s*(or|OR)\s*'?\d+'?\s*=\s*'?\d+'?)/i,
    /('\s*(or|OR)\s+\d+\s*=\s*\d+)/i,
    /(--\s*$)/,
    /;\s*(drop|DROP|alter|ALTER|delete|DELETE|truncate|TRUNCATE|insert|INSERT|update|UPDATE)\s+/i,
    /\b(drop\s+table|DROP\s+TABLE)\b/i,
    /\b(union\s+select|UNION\s+SELECT)\b/i,
    /\bxp_\w+/i,
    /\b(exec|EXEC|execute|EXECUTE)\s*\(/i,
    /\b(cast|CAST)\s*\(/i,
    /char\s*\(\s*\d+/i,
    /\bor\s+1\s*=\s*1\b/i,
    /'\s*;\s*--/,
    /\bselect\s+.*\bfrom\b/i,
    /\binsert\s+into\b/i,
    /\bdelete\s+from\b/i,
    /\bupdate\s+\w+\s+set\b/i,
    /\bwaitfor\s+delay\b/i,
    /\bbenchmark\s*\(/i
  ];

  // XSS patterns
  var XSS_PATTERNS = [
    /<script[\s>]/i,
    /<\/script>/i,
    /javascript\s*:/i,
    /on\w+\s*=/i,
    /eval\s*\(/i,
    /document\s*\.\s*cookie/i,
    /alert\s*\(/i,
    /<iframe/i,
    /<object/i,
    /<embed/i,
    /data\s*:\s*text\/html/i,
    /vbscript\s*:/i,
    /<img[^>]+src[^>]*=/i,
    /expression\s*\(/i,
    /&#\d+;/,
    /&\w+;/,
    /<svg[\s>]/i,
    /window\s*\[/i,
    /\bfetch\s*\(/i,
    /\bxmlhttprequest\b/i
  ];

  // Path traversal patterns
  var PATH_PATTERNS = [
    /\.\.\//,
    /\.\.\\/,
    /%2e%2e/i,
    /%252e/i,
    /\.\.%2f/i,
    /\.\.%5c/i
  ];

  // Null byte patterns
  var NULL_BYTE_PATTERNS = [
    /%00/,
    /\x00/,
    /\\0/
  ];

  /* ══ SECTION 2: UTILITY FUNCTIONS ════════════════════════════════════════════ */

  function deepMerge(target, source) {
    var result = {};
    for (var k in target) {
      if (Object.prototype.hasOwnProperty.call(target, k)) {
        result[k] = target[k];
      }
    }
    for (var k2 in source) {
      if (Object.prototype.hasOwnProperty.call(source, k2)) {
        if (source[k2] !== null && typeof source[k2] === 'object' && !Array.isArray(source[k2])) {
          result[k2] = deepMerge(target[k2] || {}, source[k2]);
        } else {
          result[k2] = source[k2];
        }
      }
    }
    return result;
  }

  function generateId(prefix) {
    return (prefix || 'fs') + '-' + Math.random().toString(36).substr(2, 9) + '-' + Date.now();
  }

  function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
  }

  function now() {
    return Date.now();
  }

  function formatDate(ts) {
    var d = new Date(ts);
    return d.toISOString().replace('T', ' ').substring(0, 19);
  }

  function getPageUrl() {
    return window.location.href;
  }

  function getUserAgent() {
    return navigator.userAgent;
  }

  function getIpHint() {
    var meta = document.querySelector('meta[name="client-ip"]');
    return meta ? meta.getAttribute('content') : 'unknown';
  }

  function arrayBufferToBase64(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = '';
    for (var i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  function base64ToArrayBuffer(b64) {
    var binary = window.atob(b64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function pemToArrayBuffer(pem) {
    var b64 = pem
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/-----BEGIN RSA PUBLIC KEY-----/, '')
      .replace(/-----END RSA PUBLIC KEY-----/, '')
      .replace(/\s+/g, '');
    return base64ToArrayBuffer(b64);
  }

  function downloadFile(filename, content, mimeType) {
    var blob = new Blob([content], { type: mimeType });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /* ══ SECTION 3: STYLE INJECTION ══════════════════════════════════════════════ */

  var STYLES_INJECTED = false;

  function injectStyles(config) {
    if (STYLES_INJECTED) return;
    STYLES_INJECTED = true;

    var tc = config.toastColors;
    var mc = config.modalColors;
    var pos = config.toastPosition || 'top-right';

    var posCSS = '';
    if (pos === 'top-right')     { posCSS = 'top:20px;right:20px;align-items:flex-end;'; }
    else if (pos === 'top-left') { posCSS = 'top:20px;left:20px;align-items:flex-start;'; }
    else if (pos === 'bottom-right') { posCSS = 'bottom:20px;right:20px;align-items:flex-end;flex-direction:column-reverse;'; }
    else if (pos === 'bottom-left')  { posCSS = 'bottom:20px;left:20px;align-items:flex-start;flex-direction:column-reverse;'; }
    else if (pos === 'top-center')   { posCSS = 'top:20px;left:50%;transform:translateX(-50%);align-items:center;'; }

    var css = [
      /* Toast Container */
      '#fs-toast-container {',
      '  position:fixed;' + posCSS,
      '  z-index:2147483647;',
      '  display:flex;',
      '  flex-direction:column;',
      '  gap:10px;',
      '  pointer-events:none;',
      '  max-width:380px;',
      '  width:auto;',
      '}',

      /* Toast */
      '.fs-toast {',
      '  pointer-events:all;',
      '  display:flex;',
      '  align-items:flex-start;',
      '  gap:10px;',
      '  padding:14px 16px 18px 16px;',
      '  border-radius:' + (tc.borderRadius || '10px') + ';',
      '  font-size:' + (tc.fontSize || '14px') + ';',
      '  font-family:inherit;',
      '  color:' + (tc.text || '#ffffff') + ';',
      '  min-width:280px;',
      '  max-width:380px;',
      '  box-shadow:0 8px 32px rgba(0,0,0,0.35),0 2px 8px rgba(0,0,0,0.2);',
      '  position:relative;',
      '  overflow:hidden;',
      '  animation:fs-slide-in 0.35s cubic-bezier(0.34,1.56,0.64,1) forwards;',
      '  box-sizing:border-box;',
      '}',
      '.fs-toast.fs-toast-hiding {',
      '  animation:fs-slide-out 0.3s ease-in forwards;',
      '}',

      /* Toast icon */
      '.fs-toast-icon {',
      '  font-size:20px;',
      '  flex-shrink:0;',
      '  line-height:1.2;',
      '  margin-top:1px;',
      '}',

      /* Toast body */
      '.fs-toast-body {',
      '  flex:1;',
      '  line-height:1.45;',
      '  word-break:break-word;',
      '  font-weight:500;',
      '}',

      /* Toast close */
      '.fs-toast-close {',
      '  flex-shrink:0;',
      '  background:none;',
      '  border:none;',
      '  color:rgba(255,255,255,0.75);',
      '  cursor:pointer;',
      '  font-size:18px;',
      '  padding:0;',
      '  line-height:1;',
      '  margin-top:-1px;',
      '  transition:color 0.2s;',
      '}',
      '.fs-toast-close:hover { color:#fff; }',

      /* Toast progress bar */
      '.fs-toast-progress {',
      '  position:absolute;',
      '  bottom:0;',
      '  left:0;',
      '  height:3px;',
      '  background:rgba(255,255,255,0.5);',
      '  border-radius:0 0 ' + (tc.borderRadius || '10px') + ' ' + (tc.borderRadius || '10px') + ';',
      '  transition:width linear;',
      '}',

      /* Modal Overlay */
      '.fs-modal-overlay {',
      '  position:fixed;',
      '  inset:0;',
      '  background:' + (mc.overlay || 'rgba(0,0,0,0.7)') + ';',
      '  backdrop-filter:blur(4px);',
      '  -webkit-backdrop-filter:blur(4px);',
      '  z-index:2147483646;',
      '  display:flex;',
      '  align-items:center;',
      '  justify-content:center;',
      '  padding:20px;',
      '  box-sizing:border-box;',
      '  animation:fs-fade-in 0.25s ease forwards;',
      '}',
      '.fs-modal-overlay.fs-modal-hiding {',
      '  animation:fs-fade-out 0.2s ease forwards;',
      '}',

      /* Modal Box */
      '.fs-modal-box {',
      '  background:' + (mc.background || '#1a1a2e') + ';',
      '  border:1.5px solid ' + (mc.border || '#e74c3c') + ';',
      '  border-radius:16px;',
      '  padding:32px;',
      '  max-width:520px;',
      '  width:100%;',
      '  box-shadow:0 24px 80px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.04);',
      '  animation:fs-modal-pop 0.35s cubic-bezier(0.34,1.56,0.64,1) forwards;',
      '  box-sizing:border-box;',
      '  position:relative;',
      '}',

      /* Modal icon */
      '.fs-modal-icon {',
      '  font-size:48px;',
      '  text-align:center;',
      '  margin-bottom:16px;',
      '  display:block;',
      '}',

      /* Modal title */
      '.fs-modal-title {',
      '  color:' + (mc.title || '#e74c3c') + ';',
      '  font-size:22px;',
      '  font-weight:700;',
      '  text-align:center;',
      '  margin:0 0 12px 0;',
      '  font-family:inherit;',
      '}',

      /* Modal description */
      '.fs-modal-desc {',
      '  color:' + (mc.text || '#cccccc') + ';',
      '  font-size:14px;',
      '  line-height:1.6;',
      '  text-align:center;',
      '  margin:0 0 18px 0;',
      '  font-family:inherit;',
      '}',

      /* Threat detail box */
      '.fs-modal-detail {',
      '  background:rgba(0,0,0,0.35);',
      '  border:1px solid ' + (mc.accent || '#8e44ad') + ';',
      '  border-radius:8px;',
      '  padding:14px 16px;',
      '  margin-bottom:22px;',
      '  font-family:monospace;',
      '  font-size:12px;',
      '  color:' + (mc.accent || '#8e44ad') + ';',
      '  line-height:1.7;',
      '  word-break:break-all;',
      '}',
      '.fs-modal-detail-row {',
      '  display:flex;',
      '  gap:8px;',
      '  margin-bottom:4px;',
      '}',
      '.fs-modal-detail-row:last-child { margin-bottom:0; }',
      '.fs-modal-detail-label {',
      '  color:rgba(255,255,255,0.5);',
      '  min-width:110px;',
      '  flex-shrink:0;',
      '}',
      '.fs-modal-detail-value {',
      '  color:' + (mc.accent || '#8e44ad') + ';',
      '}',

      /* Modal buttons */
      '.fs-modal-buttons {',
      '  display:flex;',
      '  gap:12px;',
      '  justify-content:center;',
      '  flex-wrap:wrap;',
      '}',
      '.fs-modal-btn {',
      '  padding:11px 28px;',
      '  border-radius:8px;',
      '  border:none;',
      '  font-size:14px;',
      '  font-weight:600;',
      '  cursor:pointer;',
      '  font-family:inherit;',
      '  transition:opacity 0.2s, transform 0.15s;',
      '  min-width:100px;',
      '}',
      '.fs-modal-btn:hover { opacity:0.85; transform:translateY(-1px); }',
      '.fs-modal-btn:active { transform:translateY(0); }',
      '.fs-modal-btn-primary {',
      '  background:' + (mc.buttonPrimary || '#e74c3c') + ';',
      '  color:#fff;',
      '}',
      '.fs-modal-btn-secondary {',
      '  background:' + (mc.buttonSecondary || '#444') + ';',
      '  color:#ddd;',
      '}',

      /* Countdown display */
      '.fs-countdown {',
      '  font-size:28px;',
      '  font-weight:700;',
      '  text-align:center;',
      '  color:' + (mc.title || '#e74c3c') + ';',
      '  margin:8px 0 4px;',
      '  display:block;',
      '  font-family:monospace;',
      '}',

      /* Animations */
      '@keyframes fs-slide-in {',
      '  from { opacity:0; transform:translateX(60px) scale(0.92); }',
      '  to   { opacity:1; transform:translateX(0)   scale(1); }',
      '}',
      '@keyframes fs-slide-out {',
      '  from { opacity:1; transform:translateX(0) scale(1); max-height:200px; margin-bottom:0; }',
      '  to   { opacity:0; transform:translateX(60px) scale(0.88); max-height:0; margin-bottom:-10px; }',
      '}',
      '@keyframes fs-fade-in {',
      '  from { opacity:0; }',
      '  to   { opacity:1; }',
      '}',
      '@keyframes fs-fade-out {',
      '  from { opacity:1; }',
      '  to   { opacity:0; }',
      '}',
      '@keyframes fs-modal-pop {',
      '  from { opacity:0; transform:scale(0.88) translateY(20px); }',
      '  to   { opacity:1; transform:scale(1)    translateY(0); }',
      '}',
      '@keyframes fs-progress {',
      '  from { width:100%; }',
      '  to   { width:0%; }',
      '}',

      /* Honeypot — screen-reader safe but visually hidden */
      '.fs-honeypot-wrap {',
      '  position:absolute;',
      '  left:-9999px;',
      '  top:-9999px;',
      '  width:1px;',
      '  height:1px;',
      '  overflow:hidden;',
      '  opacity:0;',
      '  pointer-events:none;',
      '  tab-index:-1;',
      '}',

      /* Mobile */
      '@media (max-width:480px) {',
      '  .fs-modal-box { padding:22px 18px; }',
      '  .fs-modal-title { font-size:18px; }',
      '  #fs-toast-container { max-width:calc(100vw - 32px); }',
      '  .fs-toast { min-width:unset; width:100%; }',
      '}'
    ].join('\n');

    var styleEl = document.createElement('style');
    styleEl.id = 'formshield-styles';
    styleEl.textContent = css;
    document.head.appendChild(styleEl);
  }

  /* ══ SECTION 4: TOAST SYSTEM ═════════════════════════════════════════════════ */

  var toastContainer = null;
  var toastQueue = [];
  var activeConfig = {};

  function getOrCreateToastContainer() {
    if (!toastContainer) {
      toastContainer = document.createElement('div');
      toastContainer.id = 'fs-toast-container';
      document.body.appendChild(toastContainer);
    }
    return toastContainer;
  }

  function showToast(type, message, options) {
    var config = activeConfig || {};
    var tc = (config.toastColors) ? deepMerge(DEFAULTS.toastColors, config.toastColors) : DEFAULTS.toastColors;
    var duration = (options && options.duration != null) ? options.duration : (config.toastDuration || 4000);
    var container = getOrCreateToastContainer();

    var colors = {
      success:  tc.success  || '#2ecc71',
      warning:  tc.warning  || '#f39c12',
      error:    tc.error    || '#e74c3c',
      security: tc.security || '#8e44ad',
      info:     tc.info     || '#3498db'
    };
    var icons = {
      success: '✓',
      warning: '⚠',
      error: '✕',
      security: '🛡',
      info: 'ℹ'
    };

    var bgColor = (options && options.backgroundColor) ? options.backgroundColor : colors[type] || colors.info;

    var toastId = generateId('fs-toast');
    var toast = document.createElement('div');
    toast.className = 'fs-toast';
    toast.id = toastId;
    toast.style.background = bgColor;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');

    var iconEl = document.createElement('span');
    iconEl.className = 'fs-toast-icon';
    iconEl.textContent = icons[type] || 'ℹ';

    var bodyEl = document.createElement('span');
    bodyEl.className = 'fs-toast-body';
    bodyEl.textContent = message;

    var closeEl = document.createElement('button');
    closeEl.className = 'fs-toast-close';
    closeEl.setAttribute('aria-label', 'Close notification');
    closeEl.textContent = '×';
    closeEl.addEventListener('click', function () {
      removeToast(toast);
    });

    var progressEl = document.createElement('div');
    progressEl.className = 'fs-toast-progress';

    toast.appendChild(iconEl);
    toast.appendChild(bodyEl);
    toast.appendChild(closeEl);
    toast.appendChild(progressEl);
    container.appendChild(toast);

    // Animate progress bar
    if (duration > 0) {
      progressEl.style.width = '100%';
      progressEl.style.transition = 'width ' + duration + 'ms linear';
      // Force reflow
      progressEl.getBoundingClientRect();
      progressEl.style.width = '0%';

      var timer = setTimeout(function () {
        removeToast(toast);
      }, duration);

      toast._fsTimer = timer;
    }

    return toast;
  }

  function removeToast(toastEl) {
    if (!toastEl || toastEl._fsRemoving) return;
    toastEl._fsRemoving = true;
    if (toastEl._fsTimer) clearTimeout(toastEl._fsTimer);
    toastEl.classList.add('fs-toast-hiding');
    setTimeout(function () {
      if (toastEl.parentNode) {
        toastEl.parentNode.removeChild(toastEl);
      }
    }, 350);
  }

  var Toast = {
    success: function (msg, opts) { return showToast('success', msg, opts); },
    error: function (msg, opts) { return showToast('error', msg, opts); },
    warning: function (msg, opts) { return showToast('warning', msg, opts); },
    security: function (msg, opts) { return showToast('security', msg, opts); },
    info: function (msg, opts) { return showToast('info', msg, opts); }
  };

  /* ══ SECTION 5: MODAL SYSTEM ═════════════════════════════════════════════════ */

  var activeModal = null;

  function showModal(opts, config) {
    if (activeModal) closeModal(activeModal);

    var mc = (config && config.modalColors)
      ? deepMerge(DEFAULTS.modalColors, config.modalColors)
      : DEFAULTS.modalColors;

    var overlay = document.createElement('div');
    overlay.className = 'fs-modal-overlay';
    overlay.id = generateId('fs-modal');
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-labelledby', overlay.id + '-title');

    var box = document.createElement('div');
    box.className = 'fs-modal-box';

    // Update colors dynamically
    box.style.background = mc.background || '#1a1a2e';
    box.style.borderColor = mc.border || '#e74c3c';

    var iconEl = document.createElement('span');
    iconEl.className = 'fs-modal-icon';
    iconEl.textContent = opts.icon || '⚠';

    var titleEl = document.createElement('h2');
    titleEl.className = 'fs-modal-title';
    titleEl.id = overlay.id + '-title';
    titleEl.textContent = opts.title || 'Security Alert';
    titleEl.style.color = mc.title || '#e74c3c';

    var descEl = document.createElement('p');
    descEl.className = 'fs-modal-desc';
    descEl.textContent = opts.description || '';
    descEl.style.color = mc.text || '#cccccc';

    box.appendChild(iconEl);
    box.appendChild(titleEl);
    box.appendChild(descEl);

    // Threat detail box
    if (opts.details && opts.details.length > 0) {
      var detailBox = document.createElement('div');
      detailBox.className = 'fs-modal-detail';
      detailBox.style.borderColor = mc.accent || '#8e44ad';

      opts.details.forEach(function (d) {
        var row = document.createElement('div');
        row.className = 'fs-modal-detail-row';

        var label = document.createElement('span');
        label.className = 'fs-modal-detail-label';
        label.textContent = d.label + ':';

        var val = document.createElement('span');
        val.className = 'fs-modal-detail-value';
        val.textContent = d.value;
        val.style.color = mc.accent || '#8e44ad';

        row.appendChild(label);
        row.appendChild(val);
        detailBox.appendChild(row);
      });

      box.appendChild(detailBox);
    }

    // Extra content (e.g. countdown)
    if (opts.extraHtml) {
      var extraEl = document.createElement('div');
      extraEl.style.textAlign = 'center';
      extraEl.style.marginBottom = '16px';
      if (opts.extraRef) {
        opts.extraRef(extraEl);
      }
      box.appendChild(extraEl);
    }

    // Buttons
    var btnWrap = document.createElement('div');
    btnWrap.className = 'fs-modal-buttons';

    var dismissBtn = document.createElement('button');
    dismissBtn.className = 'fs-modal-btn fs-modal-btn-primary';
    dismissBtn.textContent = opts.dismissLabel || 'Dismiss';
    dismissBtn.style.background = mc.buttonPrimary || '#e74c3c';
    dismissBtn.addEventListener('click', function () {
      closeModal(overlay);
      if (opts.onDismiss) opts.onDismiss();
    });
    btnWrap.appendChild(dismissBtn);

    if (opts.reportLabel) {
      var reportBtn = document.createElement('button');
      reportBtn.className = 'fs-modal-btn fs-modal-btn-secondary';
      reportBtn.textContent = opts.reportLabel;
      reportBtn.style.background = mc.buttonSecondary || '#444';
      reportBtn.addEventListener('click', function () {
        if (opts.onReport) opts.onReport();
        closeModal(overlay);
      });
      btnWrap.appendChild(reportBtn);
    }

    box.appendChild(btnWrap);
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    activeModal = overlay;

    // Close on overlay click
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) closeModal(overlay);
    });

    // Close on Escape
    var escHandler = function (e) {
      if (e.key === 'Escape') {
        closeModal(overlay);
        document.removeEventListener('keydown', escHandler);
      }
    };
    document.addEventListener('keydown', escHandler);
    overlay._escHandler = escHandler;

    dismissBtn.focus();
    return overlay;
  }

  function closeModal(overlayEl) {
    if (!overlayEl || overlayEl._fsClosing) return;
    overlayEl._fsClosing = true;
    if (overlayEl._escHandler) document.removeEventListener('keydown', overlayEl._escHandler);
    overlayEl.classList.add('fs-modal-hiding');
    setTimeout(function () {
      if (overlayEl.parentNode) overlayEl.parentNode.removeChild(overlayEl);
      if (activeModal === overlayEl) activeModal = null;
    }, 250);
  }

  function showInjectionModal(formId, fieldName, pattern, category, config) {
    return showModal({
      icon: '⚠',
      title: '⚠ Suspicious Input Detected',
      description: 'A potentially malicious pattern was detected in your submission. This incident has been logged for security review.',
      details: [
        { label: 'Form ID', value: formId || 'unknown' },
        { label: 'Field Name', value: fieldName || 'unknown' },
        { label: 'Threat Category', value: category || 'injection' },
        { label: 'Matched Pattern', value: pattern || 'suspicious content' }
      ],
      dismissLabel: 'Dismiss',
      reportLabel: 'Report & Dismiss'
    }, config);
  }

  function showBotModal(score, signals, config) {
    return showModal({
      icon: '🤖',
      title: '🤖 Automated Behavior Detected',
      description: 'This submission appears to originate from an automated process rather than a human user. Your session has been flagged.',
      details: [
        { label: 'Suspicion Score', value: score + ' / 100' },
        { label: 'Signals Triggered', value: signals.join(', ') || 'none' }
      ],
      dismissLabel: 'I\'m Human — Retry'
    }, config);
  }

  function showLockoutModal(formId, attemptCount, nextRetryMs, config, onCountdownEnd) {
    var countdownRef = { el: null, interval: null };

    return showModal({
      icon: '🔒',
      title: '🔒 Access Temporarily Blocked',
      description: 'Too many failed attempts have been detected. Access to this form has been temporarily restricted.',
      details: [
        { label: 'Form ID', value: formId || 'unknown' },
        { label: 'Attempts Made', value: String(attemptCount) },
        { label: 'Next Retry At', value: new Date(nextRetryMs).toLocaleTimeString() }
      ],
      extraHtml: true,
      extraRef: function (el) {
        var span = document.createElement('span');
        span.className = 'fs-countdown';
        el.appendChild(span);
        countdownRef.el = span;

        countdownRef.interval = setInterval(function () {
          var remaining = Math.max(0, nextRetryMs - Date.now());
          var secs = Math.ceil(remaining / 1000);
          var mins = Math.floor(secs / 60);
          var s = secs % 60;
          span.textContent = (mins > 0 ? mins + 'm ' : '') + s + 's remaining';
          if (remaining <= 0) {
            clearInterval(countdownRef.interval);
            span.textContent = 'Lockout lifted — you may retry now.';
            if (onCountdownEnd) onCountdownEnd();
          }
        }, 500);
      },
      dismissLabel: 'Acknowledge',
      onDismiss: function () {
        if (countdownRef.interval) clearInterval(countdownRef.interval);
      }
    }, config);
  }

  function showTamperModal(description, config) {
    return showModal({
      icon: '⚠',
      title: '⚠ Form Integrity Violation',
      description: 'The structure of this form has been modified after initialization. This may indicate a client-side attack.',
      details: [
        { label: 'Detected Change', value: description || 'unknown modification' }
      ],
      dismissLabel: 'Dismiss'
    }, config);
  }

  /* ══ SECTION 6: INPUT SANITIZER ══════════════════════════════════════════════ */

  function checkPatterns(value, patterns, category) {
    for (var i = 0; i < patterns.length; i++) {
      if (patterns[i].test(value)) {
        return { matched: true, pattern: patterns[i].toString(), category: category };
      }
    }
    return { matched: false };
  }

  function detectExcessiveRepeat(value, threshold) {
    threshold = threshold || 20;
    var match = value.match(/(.)\1+/g);
    if (match) {
      for (var i = 0; i < match.length; i++) {
        if (match[i].length >= threshold) return true;
      }
    }
    return false;
  }

  function stripDangerousContent(value) {
    // Strip XSS tags and attributes
    value = value.replace(/<script[\s\S]*?<\/script>/gi, '');
    value = value.replace(/<[^>]+>/g, '');
    value = value.replace(/javascript:/gi, '');
    value = value.replace(/on\w+\s*=/gi, '');
    value = value.replace(/eval\s*\(/gi, '');
    // Strip path traversal
    value = value.replace(/\.\.\//g, '');
    value = value.replace(/\.\.\\/g, '');
    value = value.replace(/%2e%2e/gi, '');
    // Strip null bytes
    value = value.replace(/%00/g, '');
    value = value.replace(/\x00/g, '');
    value = value.replace(/\\0/g, '');
    return value;
  }

  function sanitizeField(fieldEl, config, formId, onBlock) {
    var value = fieldEl.value;
    var fieldName = fieldEl.name || fieldEl.id || 'unknown';
    var maxLen = config.maxInputLength || 255;

    // Max length enforcement
    if (value.length > maxLen) {
      if (config.sanitizeMode === 'strip') {
        fieldEl.value = value.substring(0, maxLen);
        return { blocked: false, stripped: true };
      } else {
        onBlock(fieldName, 'Exceeds maximum length of ' + maxLen, 'length');
        return { blocked: true };
      }
    }

    // Check patterns
    var checks = [
      { patterns: SQL_PATTERNS, category: 'SQL Injection' },
      { patterns: XSS_PATTERNS, category: 'XSS Attack' },
      { patterns: PATH_PATTERNS, category: 'Path Traversal' },
      { patterns: NULL_BYTE_PATTERNS, category: 'Null Byte Injection' }
    ];

    for (var i = 0; i < checks.length; i++) {
      var result = checkPatterns(value, checks[i].patterns, checks[i].category);
      if (result.matched) {
        if (config.sanitizeMode === 'strip') {
          fieldEl.value = stripDangerousContent(value);
          return { blocked: false, stripped: true };
        } else {
          onBlock(fieldName, result.pattern, result.category);
          return { blocked: true, fieldName: fieldName, pattern: result.pattern, category: result.category };
        }
      }
    }

    // Custom patterns
    var custom = config.customBlockPatterns || [];
    for (var j = 0; j < custom.length; j++) {
      var re = (custom[j] instanceof RegExp) ? custom[j] : new RegExp(custom[j], 'i');
      if (re.test(value)) {
        if (config.sanitizeMode === 'strip') {
          fieldEl.value = value.replace(re, '');
          return { blocked: false, stripped: true };
        } else {
          onBlock(fieldName, re.toString(), 'Custom Pattern');
          return { blocked: true, fieldName: fieldName, pattern: re.toString(), category: 'Custom Pattern' };
        }
      }
    }

    // Excessive repeat
    if (detectExcessiveRepeat(value, 20)) {
      if (config.sanitizeMode === 'strip') {
        fieldEl.value = value.replace(/(.)\1{19,}/g, function (m, c) { return c.repeat(5); });
        return { blocked: false, stripped: true };
      } else {
        onBlock(fieldName, 'aaaa...repeated chars', 'Spam/Flood Pattern');
        return { blocked: true, fieldName: fieldName, pattern: 'Excessive repeated characters', category: 'Spam/Flood' };
      }
    }

    return { blocked: false };
  }

  /* ══ SECTION 7: RSA ENCRYPTION ═══════════════════════════════════════════════ */

  /* ── COMPANION PHP DECRYPTION SNIPPET ──────────────────────────────────────

  Save as get-public-key.php — serves the RSA public key to the browser:

  <?php
  header('Content-Type: application/json');
  header('Access-Control-Allow-Origin: *');

  // Load your private key file (keep this outside webroot!)
  $privateKeyPem = file_get_contents('/path/to/private_key.pem');
  $privateKey    = openssl_pkey_get_private($privateKeyPem);
  $keyDetails    = openssl_pkey_get_details($privateKey);

  echo json_encode(['publicKey' => $keyDetails['key']]);
  ?>

  ──────────────────────────────────────────────────────────────────────────────

  Save as decrypt-handler.php — decrypts the submitted password on your server:

  <?php
  // Load private key
  $privateKeyPem = file_get_contents('/path/to/private_key.pem');
  $privateKey    = openssl_pkey_get_private($privateKeyPem);

  // Get encrypted value from POST (base64-encoded)
  $encryptedB64 = $_POST['password'] ?? '';
  $encrypted    = base64_decode($encryptedB64);

  // Decrypt using OAEP + SHA-256
  $decrypted = '';
  if (openssl_private_decrypt($encrypted, $decrypted, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
      $plainPassword = $decrypted;
      // Use $plainPassword for authentication ...
  } else {
      // Decryption failed — reject request
      http_response_code(400);
      exit('Decryption failed');
  }

  // Generate RSA key pair (run once from CLI):
  // openssl genrsa -out private_key.pem 2048
  // openssl rsa -in private_key.pem -pubout -out public_key.pem
  ?>

  ─────────────────────────────────────────────────────────────────────────── */

  function fetchPublicKey(endpoint) {
    return fetch(endpoint, {
      method: 'GET',
      headers: { 'Accept': 'application/json', 'X-Requested-With': 'FormShield' }
    })
    .then(function (res) {
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res.json();
    })
    .then(function (data) {
      var pem = data.publicKey || data.public_key || data.key || data;
      if (typeof pem !== 'string') throw new Error('Invalid key format');
      return pem;
    });
  }

  function importPublicKey(pem) {
    if (!window.crypto || !window.crypto.subtle) {
      return Promise.reject(new Error('Web Crypto API not available'));
    }
    var keyData = pemToArrayBuffer(pem);
    return window.crypto.subtle.importKey(
      'spki',
      keyData,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );
  }

  function encryptValue(cryptoKey, plaintext) {
    var encoder = new TextEncoder();
    var data = encoder.encode(plaintext);
    return window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      cryptoKey,
      data
    ).then(function (encrypted) {
      return arrayBufferToBase64(encrypted);
    });
  }

  function setupEncryption(config, formEl) {
    if (!config.enableEncryption) return Promise.resolve(null);
    if (!window.crypto || !window.crypto.subtle) {
      Toast.warning('Web Crypto API unavailable — encryption disabled.', { duration: 5000 });
      return Promise.resolve(null);
    }

    return fetchPublicKey(config.rsaEndpoint)
      .then(function (pem) {
        return importPublicKey(pem);
      })
      .then(function (cryptoKey) {
        if (config.onEncryptionReady) config.onEncryptionReady();
        return cryptoKey;
      })
      .catch(function (err) {
        logEvent({ eventType: 'rsa_fail', formId: config.formId, detail: err.message }, config);
        if (config.rsaFailMode === 'block') {
          Toast.security('RSA key fetch failed — form submission blocked for security.', { duration: 0 });
          return null;
        } else {
          Toast.warning('Encryption unavailable — submitting without encryption.', { duration: 5000 });
          return null;
        }
      });
  }

  function encryptFormFields(cryptoKey, formEl, fieldsToEncrypt) {
    if (!cryptoKey) return Promise.resolve(false);
    var promises = [];
    var fields = fieldsToEncrypt || ['password'];

    fields.forEach(function (fieldName) {
      var field = formEl.querySelector('[name="' + fieldName + '"]');
      if (!field || !field.value) return;
      var p = encryptValue(cryptoKey, field.value).then(function (encrypted) {
        field.value = encrypted;
      });
      promises.push(p);
    });

    return Promise.all(promises).then(function () {
      // Add marker hidden field
      var existing = formEl.querySelector('[name="_formshield_encrypted"]');
      if (!existing) {
        var hidden = document.createElement('input');
        hidden.type = 'hidden';
        hidden.name = '_formshield_encrypted';
        hidden.value = 'true';
        hidden.id = 'fs-enc-marker';
        formEl.appendChild(hidden);
      }
      return true;
    });
  }

  /* ══ SECTION 8: BOT DETECTION ════════════════════════════════════════════════ */

  function BotDetector(formEl, config) {
    var self = this;
    self.formId = config.formId;
    self.config = config;
    self.renderTime = now();
    self.firstInteractionTime = null;
    self.hasMouse = false;
    self.hasKeyboard = false;
    self.fieldFillTimes = {};
    self.suspicionScore = 0;
    self.signals = [];
    self.honeypotValue = '';
    self.destroyed = false;

    // Inject honeypot
    var hpWrap = document.createElement('div');
    hpWrap.className = 'fs-honeypot-wrap';
    hpWrap.id = 'fs-honeypot-wrap-' + config.formId;
    hpWrap.setAttribute('aria-hidden', 'true');

    var hpField = document.createElement('input');
    hpField.type = 'text';
    hpField.name = config.honeypotFieldName || 'website';
    hpField.id = 'fs-honeypot-' + config.formId;
    hpField.tabIndex = -1;
    hpField.autocomplete = 'off';
    hpField.setAttribute('aria-hidden', 'true');

    hpWrap.appendChild(hpField);
    formEl.appendChild(hpWrap);
    self.honeypotField = hpField;

    // Mouse movement listener
    self._mouseHandler = function () {
      if (!self.destroyed) self.hasMouse = true;
    };
    formEl.addEventListener('mousemove', self._mouseHandler, { passive: true });

    // Keyboard listener
    self._keyHandler = function () {
      if (self.destroyed) return;
      if (!self.firstInteractionTime) self.firstInteractionTime = now();
      self.hasKeyboard = true;
    };
    formEl.addEventListener('keydown', self._keyHandler, { passive: true });

    // Touch listener (mobile humans)
    self._touchHandler = function () {
      if (!self.destroyed) {
        self.hasMouse = true; // treat touch as movement
        if (!self.firstInteractionTime) self.firstInteractionTime = now();
      }
    };
    formEl.addEventListener('touchstart', self._touchHandler, { passive: true });

    // Track per-field fill times
    var inputs = formEl.querySelectorAll('input, textarea');
    inputs.forEach(function (inp) {
      var fieldName = inp.name || inp.id || 'field';
      inp.addEventListener('focus', function () {
        if (!self.destroyed) self.fieldFillTimes[fieldName] = { start: now() };
      }, { passive: true });
      inp.addEventListener('blur', function () {
        if (!self.destroyed && self.fieldFillTimes[fieldName]) {
          self.fieldFillTimes[fieldName].duration = now() - self.fieldFillTimes[fieldName].start;
        }
      }, { passive: true });
    });
  }

  BotDetector.prototype.evaluate = function (submitTime) {
    var self = this;
    self.suspicionScore = 0;
    self.signals = [];

    // Honeypot check
    if (self.honeypotField && self.honeypotField.value && self.honeypotField.value.length > 0) {
      self.suspicionScore += 100;
      self.signals.push('honeypot_filled');
    }

    // Timing: too fast overall
    var elapsed = submitTime - self.renderTime;
    if (elapsed < (self.config.minSubmitTimeMs || 1800)) {
      self.suspicionScore += 40;
      self.signals.push('submit_too_fast (' + elapsed + 'ms)');
    }

    // No first interaction (never touched the form)
    if (!self.firstInteractionTime) {
      self.suspicionScore += 25;
      self.signals.push('no_interaction_detected');
    }

    // Behavioral entropy: no mouse + no keyboard
    if (!self.hasMouse && !self.hasKeyboard) {
      self.suspicionScore += 30;
      self.signals.push('no_mouse_or_keyboard');
    } else if (!self.hasKeyboard) {
      self.suspicionScore += 10;
      self.signals.push('no_keyboard_events');
    } else if (!self.hasMouse) {
      self.suspicionScore += 5;
      self.signals.push('no_mouse_movement');
    }

    // Per-field fill time
    var fastFills = 0;
    for (var k in self.fieldFillTimes) {
      if (Object.prototype.hasOwnProperty.call(self.fieldFillTimes, k)) {
        var d = self.fieldFillTimes[k].duration;
        if (d !== undefined && d < 300) fastFills++;
      }
    }
    if (fastFills > 0) {
      self.suspicionScore += Math.min(fastFills * 10, 30);
      self.signals.push('fields_filled_too_fast (' + fastFills + ' fields)');
    }

    self.suspicionScore = Math.min(self.suspicionScore, 100);
    return {
      score: self.suspicionScore,
      signals: self.signals,
      isBot: self.suspicionScore >= (self.config.botSuspicionThreshold || 60)
    };
  };

  BotDetector.prototype.destroy = function (formEl) {
    this.destroyed = true;
    if (this._mouseHandler) formEl.removeEventListener('mousemove', this._mouseHandler);
    if (this._keyHandler) formEl.removeEventListener('keydown', this._keyHandler);
    if (this._touchHandler) formEl.removeEventListener('touchstart', this._touchHandler);
    var hpWrap = document.getElementById('fs-honeypot-wrap-' + this.formId);
    if (hpWrap && hpWrap.parentNode) hpWrap.parentNode.removeChild(hpWrap);
  };

  /* ══ SECTION 9: RATE LIMITER ══════════════════════════════════════════════════ */

  var LS_PREFIX = 'formshield_rl_';

  function getRateLimitData(formId) {
    try {
      var raw = localStorage.getItem(LS_PREFIX + formId);
      if (!raw) return { attempts: 0, lockedUntil: 0, lockCount: 0 };
      return JSON.parse(raw);
    } catch (e) {
      return { attempts: 0, lockedUntil: 0, lockCount: 0 };
    }
  }

  function saveRateLimitData(formId, data) {
    try {
      localStorage.setItem(LS_PREFIX + formId, JSON.stringify(data));
    } catch (e) { /* localStorage unavailable */ }
  }

  function clearLockoutData(formId) {
    try {
      localStorage.removeItem(LS_PREFIX + formId);
    } catch (e) { /* ignore */ }
  }

  function checkRateLimit(formId, config) {
    var data = getRateLimitData(formId);
    var n = now();

    if (data.lockedUntil && n < data.lockedUntil) {
      return { locked: true, data: data };
    }

    // If previous lockout expired, reset attempts
    if (data.lockedUntil && n >= data.lockedUntil) {
      data.attempts = 0;
      data.lockedUntil = 0;
      saveRateLimitData(formId, data);
    }

    return { locked: false, data: data };
  }

  function recordAttempt(formId, config) {
    var data = getRateLimitData(formId);
    data.attempts = (data.attempts || 0) + 1;

    var maxAttempts = config.maxAttempts || 5;

    if (data.attempts >= maxAttempts) {
      var lockCount = (data.lockCount || 0) + 1;
      data.lockCount = lockCount;
      var baseMs = (config.lockoutBaseMinutes || 1) * 60 * 1000;
      var duration = baseMs * Math.pow(2, lockCount - 1);
      data.lockedUntil = now() + duration;
      saveRateLimitData(formId, data);
      return { newLockout: true, lockedUntil: data.lockedUntil, attempts: data.attempts, lockCount: lockCount };
    }

    saveRateLimitData(formId, data);
    return { newLockout: false, attempts: data.attempts };
  }

  /* ══ SECTION 10: TAMPER DETECTION ════════════════════════════════════════════ */

  function TamperDetector(formEl, config) {
    var self = this;
    self.config = config;
    self.formEl = formEl;
    self.snapshot = self.takeSnapshot();
    self.observer = null;
    self.tampered = false;
    self.onTamper = null;
  }

  TamperDetector.prototype.takeSnapshot = function () {
    var fields = this.formEl.querySelectorAll('input, select, textarea');
    var snap = [];
    fields.forEach(function (f) {
      if (f.id && f.id.indexOf('fs-honeypot') !== -1) return; // ignore honeypot
      if (f.id && f.id === 'fs-enc-marker') return; // ignore our marker
      snap.push({ name: f.name || '', id: f.id || '', type: f.type || '' });
    });
    return snap;
  };

  TamperDetector.prototype.compareSnapshot = function (current) {
    var orig = this.snapshot;
    if (current.length !== orig.length) {
      var diff = current.length - orig.length;
      return {
        changed: true,
        description: diff > 0
          ? (diff + ' new field(s) injected into the form')
          : (Math.abs(diff) + ' field(s) removed from the form')
      };
    }
    for (var i = 0; i < orig.length; i++) {
      if (orig[i].name !== current[i].name) {
        return {
          changed: true,
          description: 'Field name changed: "' + orig[i].name + '" → "' + current[i].name + '"'
        };
      }
      if (orig[i].type !== current[i].type) {
        return {
          changed: true,
          description: 'Field type changed on "' + orig[i].name + '": ' + orig[i].type + ' → ' + current[i].type
        };
      }
    }
    return { changed: false };
  };

  TamperDetector.prototype.start = function (onTamperCallback) {
    var self = this;
    self.onTamper = onTamperCallback;
    var debounceTimer = null;

    if (!window.MutationObserver) return;

    self.observer = new MutationObserver(function (mutations) {
      var relevant = false;
      mutations.forEach(function (m) {
        if (m.type === 'childList' || m.type === 'attributes') {
          if (m.target !== self.formEl && m.target.tagName !== 'INPUT') {
            relevant = true;
          } else if (m.type === 'attributes' && (m.attributeName === 'name' || m.attributeName === 'type')) {
            relevant = true;
          } else if (m.type === 'childList') {
            m.addedNodes.forEach(function (n) {
              if (n.tagName === 'INPUT' || n.tagName === 'SELECT' || n.tagName === 'TEXTAREA') relevant = true;
            });
            m.removedNodes.forEach(function (n) {
              if (n.tagName === 'INPUT' || n.tagName === 'SELECT' || n.tagName === 'TEXTAREA') relevant = true;
            });
          }
        }
      });

      if (!relevant) return;
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(function () {
        var current = self.takeSnapshot();
        var result = self.compareSnapshot(current);
        if (result.changed && !self.tampered) {
          self.tampered = true;
          if (self.onTamper) self.onTamper(result.description);
        }
      }, 100);
    });

    self.observer.observe(self.formEl, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['name', 'type', 'id']
    });
  };

  TamperDetector.prototype.destroy = function () {
    if (this.observer) this.observer.disconnect();
  };

  /* ══ SECTION 11: LOGGING & REPORTING ═════════════════════════════════════════ */

  var sessionLogs = [];

  function logEvent(entry, config) {
    if (!config || !config.enableLogging) return;

    var logEntry = {
      timestamp: formatDate(now()),
      eventType: entry.eventType || 'unknown',
      formId: entry.formId || (config && config.formId) || 'unknown',
      fieldName: entry.fieldName || null,
      detail: entry.detail || null,
      userAgent: getUserAgent(),
      pageUrl: getPageUrl(),
      ipHint: getIpHint()
    };

    sessionLogs.push(logEntry);

    if (config && config.reportEndpoint && config.reportOnEvents) {
      var shouldReport = config.reportOnEvents.indexOf(logEntry.eventType) !== -1;
      if (shouldReport) {
        reportToServer(logEntry, config);
      }
    }
  }

  function reportToServer(logEntry, config) {
    var endpoint = config.reportEndpoint;
    if (!endpoint) return;

    var payload = {
      event: logEntry,
      reportDirectory: config.reportDirectory || './formshield_logs/',
      reportFilename: config.reportFilename || 'formshield_log',
      reportFileFormat: config.reportFileFormat || 'txt'
    };

    var body = (config.reportFormat === 'json')
      ? JSON.stringify(payload)
      : Object.keys(payload).map(function (k) {
          return encodeURIComponent(k) + '=' + encodeURIComponent(JSON.stringify(payload[k]));
        }).join('&');

    var headers = config.reportFormat === 'json'
      ? { 'Content-Type': 'application/json' }
      : { 'Content-Type': 'application/x-www-form-urlencoded' };

    var fetchOpts = {
      method: 'POST',
      headers: headers,
      body: body,
      keepalive: true
    };

    if (config.reportAsync !== false) {
      fetch(endpoint, fetchOpts).catch(function () { /* silent fail */ });
    } else {
      // Synchronous-ish via XHR
      try {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', endpoint, false);
        for (var h in headers) {
          if (Object.prototype.hasOwnProperty.call(headers, h)) {
            xhr.setRequestHeader(h, headers[h]);
          }
        }
        xhr.send(body);
      } catch (e) { /* ignore */ }
    }
  }

  function getLogs() {
    return sessionLogs.slice();
  }

  function exportLogs(format) {
    var logs = sessionLogs;
    var ts = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);

    if (format === 'csv') {
      var headers = ['timestamp', 'eventType', 'formId', 'fieldName', 'detail', 'userAgent', 'pageUrl', 'ipHint'];
      var rows = [headers.join(',')];
      logs.forEach(function (l) {
        var row = headers.map(function (h) {
          var val = l[h] != null ? String(l[h]) : '';
          return '"' + val.replace(/"/g, '""') + '"';
        });
        rows.push(row.join(','));
      });
      downloadFile('formshield_logs_' + ts + '.csv', rows.join('\n'), 'text/csv');
    } else {
      downloadFile('formshield_logs_' + ts + '.json', JSON.stringify(logs, null, 2), 'application/json');
    }
  }

  /* ══ COMPANION PHP LOGGER (paste into your endpoint file) ═══════════════════

  <?php
  header('Access-Control-Allow-Origin: *');
  header('Content-Type: application/json');

  $data = json_decode(file_get_contents('php://input'), true);
  if (!$data) { echo json_encode(['status'=>'error']); exit; }

  $dir    = isset($data['reportDirectory']) ? $data['reportDirectory'] : './formshield_logs/';
  $format = isset($data['reportFileFormat']) ? $data['reportFileFormat'] : 'txt';
  $fname  = isset($data['reportFilename'])   ? $data['reportFilename']  : 'formshield_log';
  $date   = date('Y-m-d');
  $file   = rtrim($dir, '/') . '/' . $fname . '_' . $date . '.' . $format;

  if (!is_dir($dir)) mkdir($dir, 0755, true);

  $entry = date('Y-m-d H:i:s') . ' | ' . json_encode($data['event']) . PHP_EOL;
  file_put_contents($file, $entry, FILE_APPEND | LOCK_EX);

  echo json_encode(['status' => 'logged']);
  ?>

  ═══════════════════════════════════════════════════════════════════════════ */

  /* ══ SECTION 12: CORE INIT & PUBLIC API ══════════════════════════════════════ */

  // Registry of protected forms
  var formRegistry = {};

  function initForm(userConfig) {
    if (!userConfig || !userConfig.formId) {
      console.error('[FormShield] formId is required');
      return;
    }

    var config = deepMerge(DEFAULTS, userConfig);
    activeConfig = config;

    var formEl = document.getElementById(config.formId);
    if (!formEl) {
      console.error('[FormShield] Form not found: #' + config.formId);
      return;
    }

    // Inject styles on first init
    injectStyles(config);

    var entry = { config: config, formEl: formEl };

    // ── RSA Encryption Setup ──────────────────────────────────────────
    var cryptoKeyRef = { key: null, failed: false };
    if (config.enableEncryption) {
      setupEncryption(config, formEl).then(function (key) {
        cryptoKeyRef.key = key;
        if (!key) cryptoKeyRef.failed = true;
      });
    }

    // ── Bot Detection Setup ───────────────────────────────────────────
    var botDetector = null;
    if (config.enableBotDetection) {
      botDetector = new BotDetector(formEl, config);
      entry.botDetector = botDetector;
    }

    // ── Tamper Detection Setup ────────────────────────────────────────
    var tamperDetector = null;
    if (config.enableTamperDetection) {
      tamperDetector = new TamperDetector(formEl, config);
      tamperDetector.start(function (description) {
        logEvent({ eventType: 'tamper', formId: config.formId, detail: description }, config);
        showTamperModal(description, config);
        if (config.onThreatDetected) {
          config.onThreatDetected({ type: 'tamper', formId: config.formId, detail: description });
        }
      });
      entry.tamperDetector = tamperDetector;
    }

    // ── Rate Limit Check on Page Load ────────────────────────────────
    if (config.enableRateLimit) {
      var rlCheck = checkRateLimit(config.formId, config);
      if (rlCheck.locked) {
        var lockedData = rlCheck.data;
        showLockoutModal(config.formId, lockedData.attempts, lockedData.lockedUntil, config, null);
        Toast.security('Access temporarily blocked. Please wait.', { duration: 0 });
        disableFormSubmit(formEl, 'lockout');
      }
    }

    // ── Submit Handler ────────────────────────────────────────────────
    var submitHandler = function (e) {
      e.preventDefault();
      var submitTime = now();

      // Re-check rate limit on each submit
      if (config.enableRateLimit) {
        var rl = checkRateLimit(config.formId, config);
        if (rl.locked) {
          showLockoutModal(config.formId, rl.data.attempts, rl.data.lockedUntil, config, null);
          logEvent({ eventType: 'rate_limit', formId: config.formId, detail: 'locked' }, config);
          if (config.onThreatDetected) config.onThreatDetected({ type: 'rate_limit', formId: config.formId });
          return;
        }
      }

      // Tamper check
      if (config.enableTamperDetection && tamperDetector && tamperDetector.tampered && config.tamperBlockSubmit) {
        Toast.security('Submission blocked: form integrity violation detected.', { duration: 5000 });
        return;
      }

      // Bot detection
      if (config.enableBotDetection && botDetector) {
        var botResult = botDetector.evaluate(submitTime);
        if (botResult.isBot) {
          logEvent({ eventType: 'bot', formId: config.formId, detail: 'score:' + botResult.score + ' signals:' + botResult.signals.join(',') }, config);
          showBotModal(botResult.score, botResult.signals, config);
          Toast.security('Automated behavior detected — submission blocked.', { duration: 5000 });
          if (config.onBotDetected) config.onBotDetected(botResult.score, botResult.signals);
          if (config.onThreatDetected) config.onThreatDetected({ type: 'bot', score: botResult.score, signals: botResult.signals });
          // Record attempt
          if (config.enableRateLimit) recordAttemptAndCheck(config, formEl);
          return;
        }
      }

      // Input Sanitization
      if (config.enableSanitization) {
        var blocked = false;
        var blockInfo = null;
        var inputs = formEl.querySelectorAll('input:not([type="hidden"]), textarea');

        for (var i = 0; i < inputs.length; i++) {
          var inp = inputs[i];
          // Skip honeypot
          if (inp.id && inp.id.indexOf('fs-honeypot') !== -1) continue;
          // Skip file inputs
          if (inp.type === 'file') continue;

          var result = sanitizeField(inp, config, config.formId, function (fieldName, pattern, category) {
            logEvent({ eventType: 'injection', formId: config.formId, fieldName: fieldName, detail: category + ':' + pattern }, config);
            showInjectionModal(config.formId, fieldName, pattern, category, config);
            Toast.security('Suspicious input blocked in field "' + fieldName + '"', { duration: 5000 });
            if (config.onInjectionDetected) config.onInjectionDetected(fieldName, pattern);
            if (config.onThreatDetected) config.onThreatDetected({ type: 'injection', fieldName: fieldName, pattern: pattern, category: category });
          });

          if (result.blocked) {
            blocked = true;
            blockInfo = result;
            break;
          }
        }

        if (blocked) {
          if (config.enableRateLimit) recordAttemptAndCheck(config, formEl);
          return;
        }
      }

      // RSA Encryption
      if (config.enableEncryption) {
        if (cryptoKeyRef.failed && config.rsaFailMode === 'block') {
          Toast.security('Encryption failed — submission blocked for security.', { duration: 0 });
          return;
        }

        encryptFormFields(cryptoKeyRef.key, formEl, config.fieldsToEncrypt)
          .then(function () {
            if (config.onSubmitAllowed) {
              var fd = new FormData(formEl);
              config.onSubmitAllowed(fd);
            }
            formEl.removeEventListener('submit', submitHandler);
            formEl.submit();
          })
          .catch(function (err) {
            Toast.error('Encryption error: ' + err.message, { duration: 5000 });
          });
      } else {
        if (config.onSubmitAllowed) {
          var fd2 = new FormData(formEl);
          config.onSubmitAllowed(fd2);
        }
        formEl.removeEventListener('submit', submitHandler);
        formEl.submit();
      }
    };

    entry.submitHandler = submitHandler;
    formEl.addEventListener('submit', submitHandler);
    formRegistry[config.formId] = entry;
  }

  function recordAttemptAndCheck(config, formEl) {
    if (!config.enableRateLimit) return;
    var result = recordAttempt(config.formId, config);
    if (result.newLockout) {
      var lockedUntil = result.lockedUntil;
      showLockoutModal(config.formId, result.attempts, lockedUntil, config, function () {
        enableFormSubmit(formEl);
      });
      Toast.security('Too many attempts — account temporarily locked.', { duration: 0 });
      disableFormSubmit(formEl, 'lockout');
      logEvent({ eventType: 'lockout', formId: config.formId, detail: 'lockedUntil:' + new Date(lockedUntil).toISOString() }, config);
      if (config.onLockout) {
        var mins = Math.round((lockedUntil - now()) / 60000);
        config.onLockout(config.formId, mins);
      }
      if (config.onThreatDetected) config.onThreatDetected({ type: 'lockout', formId: config.formId, lockedUntil: lockedUntil });
    }
  }

  function disableFormSubmit(formEl, reason) {
    var btn = formEl.querySelector('[type="submit"]');
    if (btn) {
      btn.disabled = true;
      btn._fsDisabledReason = reason;
    }
    formEl._fsSubmitDisabled = true;
  }

  function enableFormSubmit(formEl) {
    var btn = formEl.querySelector('[type="submit"]');
    if (btn) {
      btn.disabled = false;
      btn._fsDisabledReason = null;
    }
    formEl._fsSubmitDisabled = false;
  }

  function destroyForm(formId) {
    var entry = formRegistry[formId];
    if (!entry) return;
    var formEl = entry.formEl;

    if (entry.submitHandler) {
      formEl.removeEventListener('submit', entry.submitHandler);
    }
    if (entry.botDetector) {
      entry.botDetector.destroy(formEl);
    }
    if (entry.tamperDetector) {
      entry.tamperDetector.destroy();
    }

    // Remove honeypot
    var hp = document.getElementById('fs-honeypot-wrap-' + formId);
    if (hp && hp.parentNode) hp.parentNode.removeChild(hp);

    // Remove enc marker
    var em = document.getElementById('fs-enc-marker');
    if (em && em.parentNode) em.parentNode.removeChild(em);

    delete formRegistry[formId];
  }

  function setColors(colorObj) {
    if (!colorObj) return;
    if (colorObj.toastColors) {
      activeConfig.toastColors = deepMerge(activeConfig.toastColors || {}, colorObj.toastColors);
    }
    if (colorObj.modalColors) {
      activeConfig.modalColors = deepMerge(activeConfig.modalColors || {}, colorObj.modalColors);
    }
    // Re-inject updated styles
    STYLES_INJECTED = false;
    var existing = document.getElementById('formshield-styles');
    if (existing && existing.parentNode) existing.parentNode.removeChild(existing);
    injectStyles(activeConfig);
  }

  /* ══════════════════════════════════════════════════════════════════════════════
     PUBLIC API
  ══════════════════════════════════════════════════════════════════════════════ */

  var FormShield = {
    version: VERSION,

    init: function (options) {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { initForm(options); });
      } else {
        initForm(options);
      }
    },

    protect: function (formId, options) {
      var opts = deepMerge(options || {}, { formId: formId });
      FormShield.init(opts);
    },

    destroy: function (formId) {
      destroyForm(formId);
    },

    clearLockout: function (formId) {
      clearLockoutData(formId);
      var entry = formRegistry[formId];
      if (entry && entry.formEl) {
        enableFormSubmit(entry.formEl);
      }
      Toast.success('Lockout cleared for form: ' + formId, { duration: 3000 });
    },

    getLogs: function () {
      return getLogs();
    },

    exportLogs: function (format) {
      exportLogs(format || 'json');
    },

    setColors: function (colorObj) {
      setColors(colorObj);
    },

    toast: Toast
  };

  return FormShield;

}));

/* ══════════════════════════════════════════════════════════════════════════════
   QUICK START EXAMPLE
   ══════════════════════════════════════════════════════════════════════════════

<form id="loginForm" method="POST" action="login.php">
  <input type="text"     name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Login</button>
</form>

<script src="FormShield.js"></script>
<script>
FormShield.init({
  formId: 'loginForm',
  rsaEndpoint: '/api/get-public-key.php',
  enableEncryption: true,
  enableBotDetection: true,
  enableRateLimit: true,
  maxAttempts: 5,
  reportEndpoint: '/api/formshield-logger.php',
  reportDirectory: './security_logs/',
  reportFileFormat: 'json',
  toastPosition: 'top-right',
  toastColors: {
    error: '#ff4757',
    security: '#5352ed',
    borderRadius: '12px'
  },
  modalColors: {
    background: '#0f0f23',
    title: '#ff4757',
    accent: '#5352ed'
  },
  onThreatDetected: function(event) {
    console.log('Threat caught:', event);
  },
  onSubmitAllowed: function(formData) {
    console.log('[FormShield] Clean submission approved.');
  }
});

// Manual API usage:
FormShield.toast.success('Login successful!');
FormShield.toast.error('Invalid credentials.');
FormShield.toast.security('Suspicious activity detected.');
FormShield.clearLockout('loginForm');
var logs = FormShield.getLogs();
FormShield.exportLogs('csv');
</script>

══════════════════════════════════════════════════════════════════════════════ */
