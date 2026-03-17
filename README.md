<div align="center">

<br/>

# 🛡️ FormShield.js

### Drop-in Form Security for Any HTML / PHP Project

<br/>

[![Version](https://img.shields.io/badge/version-1.0.0-6c63ff?style=for-the-badge&logo=github)](https://github.com/logiurl/formshield)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ecc71?style=for-the-badge)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen?style=for-the-badge&logo=javascript)](https://cdn.jsdelivr.net/gh/logiurl/formshield@main/formshield.js)
[![CDN Ready](https://img.shields.io/badge/CDN-jsDelivr-orange?style=for-the-badge&logo=jsdelivr)](https://cdn.jsdelivr.net/gh/logiurl/formshield@main/formshield.js)
[![Vanilla JS](https://img.shields.io/badge/vanilla-JS-f7df1e?style=for-the-badge&logo=javascript&logoColor=black)](https://cdn.jsdelivr.net/gh/logiurl/formshield@main/formshield.js)
[![Web Crypto API](https://img.shields.io/badge/Web_Crypto-RSA--OAEP-3498db?style=for-the-badge&logo=webauthn)](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)
[![Free to Use](https://img.shields.io/badge/free_to_use-✓-2ecc71?style=for-the-badge)](https://cdn.jsdelivr.net/gh/logiurl/formshield@main/formshield.js)

<br/>

> **One `<script>` tag. Seven security modules. Zero configuration required.**  
> Protect login forms, contact forms, and registration pages against SQL injection, XSS, bots,  
> brute-force attacks, and client-side tampering — without rebuilding your project.

<br/>

[🚀 Quick Start](#-quick-start) · [📦 Installation](#-installation) · [⚙️ Configuration](CONFIG.md) · [🔌 Public API](#-public-api) · [🖼️ Screenshots](#️-screenshots) · [📄 PHP Companion](#-php-companion-snippets)

<br/>

---

</div>

## 🔐 Security Modules

| Module | What It Does | Default |
|--------|-------------|---------|
| 🧹 **Input Sanitizer** | Blocks SQL injection, XSS, path traversal, null bytes | `enabled` |
| 🔑 **RSA Encryption** | Encrypts passwords with Web Crypto API before send | `enabled` |
| 🤖 **Bot Detection** | Honeypot, timing analysis, behavioral entropy scoring | `enabled` |
| 🔒 **Rate Limiter** | Exponential backoff lockout via `localStorage` | `enabled` |
| 🔔 **Toast Notifications** | Animated, stacked, progress-bar toasts — no `alert()` | `always on` |
| 🪟 **Security Modals** | Detailed threat modals with pattern info | `always on` |
| 👁️ **Tamper Detection** | `MutationObserver` watches for injected DOM fields | `enabled` |
| 📋 **Logging & Reporting** | In-memory logs, CSV/JSON export, PHP endpoint relay | `enabled` |

---

## 📦 Installation

### ✅ Option 1 — jsDelivr CDN (Recommended)

```html
<script src="https://cdn.jsdelivr.net/gh/logiurl/formshield@main/formshield.js"></script>
```

### Option 2 — Download & Self-Host

```html
<script src="/js/formshield.js"></script>
```

### Option 3 — Specific Version (Pinned)

```html
<script src="https://cdn.jsdelivr.net/gh/logiurl/formshield@1.0.0/formshield.js"></script>
```

> **No npm. No build step. No bundler.** Just drop the `<script>` tag before your closing `</body>` tag.

---

## 🚀 Quick Start

### Minimal Setup (30 seconds)

```html
<!-- Your form — no changes needed to the HTML -->
<form id="loginForm" method="POST" action="login.php">
  <input type="text"     name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Login</button>
</form>

<!-- 1. Load FormShield -->
<script src="https://cdn.jsdelivr.net/gh/logiurl/formshield@main/formshield.js"></script>

<!-- 2. Initialize -->
<script>
FormShield.init({
  formId: 'loginForm'
});
</script>
```

That's it. FormShield is now protecting your form with all modules active on their default settings.

---

### Full Configuration Example

```html
<script src="https://cdn.jsdelivr.net/gh/logiurl/formshield@main/formshield.js"></script>
<script>
FormShield.init({

  // ── Target Form ────────────────────────────────────────────────────
  formId: 'loginForm',
  fieldsToEncrypt: ['password'],

  // ── RSA Encryption ─────────────────────────────────────────────────
  enableEncryption: true,
  rsaEndpoint: '/api/get-public-key.php',
  rsaFailMode: 'block',              // 'block' or 'warn'

  // ── Input Sanitization ─────────────────────────────────────────────
  enableSanitization: true,
  sanitizeMode: 'block',             // 'block' or 'strip'
  maxInputLength: 255,

  // ── Bot Detection ──────────────────────────────────────────────────
  enableBotDetection: true,
  botSuspicionThreshold: 60,         // 0-100 score threshold
  minSubmitTimeMs: 1800,             // Minimum ms from page load to submit

  // ── Rate Limiting ──────────────────────────────────────────────────
  enableRateLimit: true,
  maxAttempts: 5,
  lockoutBaseMinutes: 1,             // Doubles per lockout: 1→2→4→8 min

  // ── Tamper Detection ───────────────────────────────────────────────
  enableTamperDetection: true,
  tamperBlockSubmit: true,

  // ── Toast Styling ──────────────────────────────────────────────────
  toastPosition: 'top-right',        // top-right | top-left | bottom-right | bottom-left | top-center
  toastDuration: 4000,
  toastColors: {
    error:        '#ff4757',
    security:     '#5352ed',
    success:      '#2ed573',
    warning:      '#ffa502',
    info:         '#1e90ff',
    text:         '#ffffff',
    borderRadius: '12px',
    fontSize:     '14px'
  },

  // ── Modal Styling ──────────────────────────────────────────────────
  modalColors: {
    overlay:         'rgba(0,0,0,0.75)',
    background:      '#0f0f23',
    title:           '#ff4757',
    text:            '#cccccc',
    accent:          '#5352ed',
    border:          '#ff4757',
    buttonPrimary:   '#ff4757',
    buttonSecondary: '#333355'
  },

  // ── Server Logging ─────────────────────────────────────────────────
  enableLogging: true,
  reportEndpoint: '/api/formshield-logger.php',
  reportDirectory: './security_logs/',
  reportFileFormat: 'json',
  reportOnEvents: ['injection', 'bot', 'lockout', 'tamper', 'rsa_fail', 'rate_limit'],

  // ── Callbacks ──────────────────────────────────────────────────────
  onThreatDetected: function(event) {
    console.warn('[FormShield] Threat:', event.type, event);
  },
  onBotDetected: function(score, signals) {
    console.warn('[FormShield] Bot score:', score, signals);
  },
  onInjectionDetected: function(fieldName, pattern) {
    console.warn('[FormShield] Injection in', fieldName, pattern);
  },
  onLockout: function(formId, minutesLocked) {
    console.warn('[FormShield] Lockout on', formId, 'for', minutesLocked, 'min');
  },
  onEncryptionReady: function() {
    console.log('[FormShield] RSA key loaded, encryption active.');
  },
  onSubmitAllowed: function(formData) {
    console.log('[FormShield] Clean submission approved.');
  }

});
</script>
```

---

## 🔌 Public API

### Initialization

```js
// Initialize (primary method)
FormShield.init({ formId: 'myForm', ...options });

// Alias
FormShield.protect('myForm', { ...options });
```

### Form Management

```js
// Remove all listeners, injected fields, and observers from a form
FormShield.destroy('myForm');

// Manually clear a rate-limit lockout (e.g. from an admin panel)
FormShield.clearLockout('myForm');
```

### Toast Notifications

```js
FormShield.toast.success('Profile saved successfully.');
FormShield.toast.error('Invalid username or password.');
FormShield.toast.warning('Session expires in 5 minutes.');
FormShield.toast.security('Suspicious activity detected on your account.');
FormShield.toast.info('Two-factor authentication is recommended.');

// With options
FormShield.toast.success('Done!', {
  duration: 6000,              // ms, 0 = persistent
  backgroundColor: '#1abc9c'  // override color
});
```

### Logging

```js
// Get all security events from this session
var logs = FormShield.getLogs();
console.table(logs);

// Download logs as a file
FormShield.exportLogs('json');   // → formshield_logs_2024-01-15T12-00-00.json
FormShield.exportLogs('csv');    // → formshield_logs_2024-01-15T12-00-00.csv
```

### Runtime Color Updates

```js
// Update colors at runtime without re-initializing
FormShield.setColors({
  toastColors:  { error: '#c0392b', security: '#6c5ce7' },
  modalColors:  { background: '#1e1e3f', title: '#ff6b6b' }
});
```

### Version

```js
console.log(FormShield.version); // "1.0.0"
```

---

## 🧹 Module 1 — Input Sanitizer

FormShield scans every non-hidden input field before submission against these threat categories:

| Category | Examples Caught |
|----------|----------------|
| **SQL Injection** | `' OR 1=1`, `DROP TABLE`, `UNION SELECT`, `EXEC(`, `CAST(`, `--` |
| **XSS Attack** | `<script>`, `javascript:`, `onerror=`, `eval(`, `document.cookie` |
| **Path Traversal** | `../`, `..\`, `%2e%2e`, `%252e` |
| **Null Byte** | `%00`, `\0`, null characters |
| **Spam/Flood** | Strings with 20+ consecutive repeated characters |
| **Custom Patterns** | Your own regex patterns via `customBlockPatterns` |

**Modes:**
- `sanitizeMode: 'block'` — stops submission, fires modal + toast, logs the event *(default)*
- `sanitizeMode: 'strip'` — silently removes bad characters and continues

---

## 🔑 Module 2 — RSA Encryption

FormShield encrypts password fields using the **Web Crypto API** (`SubtleCrypto`) with **RSA-OAEP + SHA-256** padding before the form is submitted. Plaintext passwords never reach the network layer.

**Flow:**
1. On `init`, fetches your RSA public key from `rsaEndpoint`
2. Imports the PEM key via `crypto.subtle.importKey`
3. On submit, encrypts each field in `fieldsToEncrypt` with `crypto.subtle.encrypt`
4. Replaces field value with Base64-encoded ciphertext
5. Injects a hidden `_formshield_encrypted=true` field for PHP to detect

**Failure modes:**
- `rsaFailMode: 'block'` — if key fetch fails, submission is blocked *(secure default)*
- `rsaFailMode: 'warn'` — if key fetch fails, warns user and submits unencrypted

See the [PHP companion snippets](#-php-companion-snippets) below for the decryption code.

---

## 🤖 Module 3 — Bot Detection

FormShield builds a **suspicion score (0–100)** from multiple signals:

| Signal | Points Added |
|--------|-------------|
| Honeypot field filled | +100 (instant block) |
| Submit triggered in under 1800ms | +40 |
| No user interaction detected | +25 |
| No mouse movement AND no keyboard events | +30 |
| No keyboard events only | +10 |
| Fields filled in under 300ms each | +10 per field (max +30) |

When score ≥ `botSuspicionThreshold` (default `60`), the bot modal is shown and submission is blocked.

**Honeypot:** A visually-hidden input (`position:absolute; left:-9999px`) with a realistic name (`website`) is injected. Bots fill it; humans never see it.

---

## 🔒 Module 4 — Rate Limiter

Protects against brute-force by tracking attempts in `localStorage` (persists across page refreshes).

| Lockout # | Duration |
|-----------|----------|
| 1st lockout | 1 minute |
| 2nd lockout | 2 minutes |
| 3rd lockout | 4 minutes |
| 4th lockout | 8 minutes |
| nth lockout | 2ⁿ⁻¹ minutes |

A live **countdown timer** is shown in the lockout modal. The submit button is disabled during lockout.

```js
// Admin override — clear lockout programmatically
FormShield.clearLockout('loginForm');
```

---

## 👁️ Module 5 — Tamper Detection

On `init`, FormShield takes a structural snapshot of your form (field names, types, count).  
A `MutationObserver` watches for any post-init DOM changes:

- ✕ New `<input>` injected into the form
- ✕ Existing field removed
- ✕ Field `name` attribute changed
- ✕ Field `type` attribute changed

If a change is detected, the **Tamper Modal** fires and (if `tamperBlockSubmit: true`) submission is blocked. This defends against client-side attacks that inject hidden fields to hijack POST data.

---

## 📋 Module 6 — Logging & Reporting

**Client-side log entry structure:**

```json
{
  "timestamp":  "2024-01-15 14:32:01",
  "eventType":  "injection",
  "formId":     "loginForm",
  "fieldName":  "username",
  "detail":     "SQL Injection:/(union\\s+select)/i",
  "userAgent":  "Mozilla/5.0 ...",
  "pageUrl":    "https://example.com/login",
  "ipHint":     "192.168.1.1"
}
```

**Event types logged:**

| eventType | Trigger |
|-----------|---------|
| `injection` | SQL/XSS/path traversal/null byte detected |
| `bot` | Suspicion score exceeded threshold |
| `lockout` | Rate limit lockout applied |
| `tamper` | Form DOM modified after init |
| `rsa_fail` | Public key fetch failed |
| `rate_limit` | Attempt during active lockout |

---

## 📄 PHP Companion Snippets

### `get-public-key.php` — Serve the RSA Public Key

```php
<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

// Store your private key OUTSIDE the webroot
$privateKeyPem = file_get_contents('/secure/keys/private_key.pem');
$privateKey    = openssl_pkey_get_private($privateKeyPem);
$keyDetails    = openssl_pkey_get_details($privateKey);

echo json_encode(['publicKey' => $keyDetails['key']]);
```

### `login.php` — Decrypt the Submitted Password

```php
<?php
// Check if FormShield encryption was used
if (isset($_POST['_formshield_encrypted']) && $_POST['_formshield_encrypted'] === 'true') {

    $privateKeyPem = file_get_contents('/secure/keys/private_key.pem');
    $privateKey    = openssl_pkey_get_private($privateKeyPem);

    $encryptedB64 = $_POST['password'] ?? '';
    $encrypted    = base64_decode($encryptedB64);

    $decrypted = '';
    if (!openssl_private_decrypt($encrypted, $decrypted, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        http_response_code(400);
        exit('Decryption failed');
    }

    $password = $decrypted; // Use for authentication

} else {
    $password = $_POST['password'] ?? ''; // Fallback if encryption not active
}
```

### `formshield-logger.php` — Receive Security Event Reports

```php
<?php
header('Access-Control-Allow-Origin: *');
header('Content-Type: application/json');

$data = json_decode(file_get_contents('php://input'), true);
if (!$data) { echo json_encode(['status' => 'error']); exit; }

$dir    = isset($data['reportDirectory'])  ? $data['reportDirectory']  : './formshield_logs/';
$format = isset($data['reportFileFormat']) ? $data['reportFileFormat'] : 'txt';
$fname  = isset($data['reportFilename'])   ? $data['reportFilename']   : 'formshield_log';
$date   = date('Y-m-d');
$file   = rtrim($dir, '/') . '/' . $fname . '_' . $date . '.' . $format;

if (!is_dir($dir)) mkdir($dir, 0755, true);

$entry = date('Y-m-d H:i:s') . ' | ' . json_encode($data['event']) . PHP_EOL;
file_put_contents($file, $entry, FILE_APPEND | LOCK_EX);

echo json_encode(['status' => 'logged']);
```

### Generate RSA Key Pair (Run Once from CLI)

```bash
# Generate 2048-bit private key
openssl genrsa -out private_key.pem 2048

# Extract public key
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Move private key OUTSIDE your webroot — e.g.
mv private_key.pem /secure/keys/private_key.pem
```

> ⚠️ **Never store `private_key.pem` inside your webroot.** Keep it outside the document root and restrict file permissions to `600`.

---

## 🎨 Theming Examples

### Dark Purple Security Theme

```js
FormShield.init({
  formId: 'loginForm',
  toastColors: {
    security:     '#7c3aed',
    error:        '#dc2626',
    warning:      '#d97706',
    success:      '#059669',
    borderRadius: '8px'
  },
  modalColors: {
    background:      '#1e1b4b',
    border:          '#7c3aed',
    title:           '#a78bfa',
    accent:          '#7c3aed',
    buttonPrimary:   '#7c3aed',
    buttonSecondary: '#374151'
  }
});
```

### Minimal Light Theme

```js
FormShield.init({
  formId: 'contactForm',
  toastPosition: 'bottom-right',
  toastColors: {
    security:     '#3b82f6',
    error:        '#ef4444',
    text:         '#1f2937',
    borderRadius: '6px',
    fontSize:     '13px'
  },
  modalColors: {
    overlay:         'rgba(0,0,0,0.5)',
    background:      '#ffffff',
    title:           '#ef4444',
    text:            '#374151',
    accent:          '#3b82f6',
    border:          '#e5e7eb',
    buttonPrimary:   '#ef4444',
    buttonSecondary: '#9ca3af'
  }
});
```

### Cyberpunk Green Theme

```js
FormShield.init({
  formId: 'loginForm',
  toastColors: {
    security:     '#00ff41',
    error:        '#ff0040',
    warning:      '#ffff00',
    success:      '#00ff41',
    text:         '#00ff41',
    borderRadius: '2px'
  },
  modalColors: {
    background:      '#0d0d0d',
    border:          '#00ff41',
    title:           '#00ff41',
    accent:          '#00ff41',
    text:            '#ccffcc',
    buttonPrimary:   '#00ff41',
    buttonSecondary: '#1a1a1a'
  }
});
```

---

## 🖼️ Screenshots

| Toast Notifications | Security Modal | Bot Detection Modal |
|---|---|---|
| Stacked, animated, with progress bar | Detailed threat info with pattern match | Suspicion score breakdown |

| Lockout Modal | Tamper Detection Alert | Injection Block |
|---|---|---|
| Live countdown timer | DOM change description | Field + pattern info |

---

## 🤝 Multi-Form Usage

```js
// Protect multiple forms independently
FormShield.init({ formId: 'loginForm',    enableEncryption: true  });
FormShield.init({ formId: 'contactForm',  enableEncryption: false });
FormShield.init({ formId: 'registerForm', maxAttempts: 3          });

// Destroy specific form protection
FormShield.destroy('contactForm');

// Clear lockout on specific form
FormShield.clearLockout('loginForm');
```

---

## 🌐 Browser Compatibility

| Browser | Version | Notes |
|---------|---------|-------|
| Chrome  | 60+ | Full support |
| Firefox | 57+ | Full support |
| Safari  | 11+ | Full support |
| Edge    | 79+ | Full support |
| Opera   | 47+ | Full support |
| IE      | ❌  | Not supported (use polyfill for `fetch` + `SubtleCrypto` if needed) |

Works alongside **jQuery**, **Bootstrap**, **Tailwind CSS**, **Alpine.js** and any other library — FormShield scopes all its CSS with `.fs-` prefix and wraps itself in an IIFE.

---

## 🔧 Framework Compatibility

```html
<!-- Works with Bootstrap forms -->
<form id="bsForm" class="needs-validation" novalidate>
  <div class="mb-3">
    <input type="text" class="form-control" name="username">
  </div>
  <button class="btn btn-primary" type="submit">Submit</button>
</form>

<!-- Works with Tailwind CSS forms -->
<form id="twForm">
  <input type="text" class="border rounded px-3 py-2 w-full" name="email">
  <button class="bg-blue-600 text-white px-4 py-2 rounded" type="submit">Send</button>
</form>
```

---

## 📁 Project Structure

```
formshield/
├── formshield.js          ← Main library (single file, all modules)
├── README.md              ← This file
├── CONFIG.md              ← Full configuration reference
├── examples/
│   ├── login-basic.html   ← Minimal login form example
│   ├── login-full.html    ← Full config example
│   └── contact-form.html  ← Contact form example
└── php/
    ├── get-public-key.php ← RSA public key endpoint
    ├── login.php          ← Decrypt + authenticate
    └── logger.php         ← Security event logging endpoint
```

---

## 📜 License

```
MIT License

Copyright (c) 2024 FormShield Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

---

<div align="center">

[![CDN](https://img.shields.io/badge/CDN-jsDelivr-orange?style=flat-square&logo=jsdelivr)](https://cdn.jsdelivr.net/gh/logiurl/formshield@main/formshield.js)
[![GitHub Stars](https://img.shields.io/github/stars/logiurl/formshield?style=flat-square&logo=github)](https://github.com/logiurl/formshield)
[![Free to Use](https://img.shields.io/badge/free_to_use-✓-2ecc71?style=flat-square)](https://cdn.jsdelivr.net/gh/logiurl/formshield@main/formshield.js)
[![Made with ❤️](https://img.shields.io/badge/made_with-❤️-red?style=flat-square)](https://github.com/logiurl/formshield)

**FormShield.js** · v1.0.0 · MIT License · Free to use in personal and commercial projects

[⬆ Back to top](#️-formshieldjs)

</div>
