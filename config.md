<div align="center">

<br/>

# ⚙️ FormShield.js — Configuration Reference

[![Version](https://img.shields.io/badge/version-1.0.0-6c63ff?style=for-the-badge)](https://github.com/logiurl/formshield)
[![CDN](https://img.shields.io/badge/CDN-jsDelivr-orange?style=for-the-badge&logo=jsdelivr)](https://cdn.jsdelivr.net/gh/logiurl/formshield@main/formshield.js)
[![Config Options](https://img.shields.io/badge/config_options-40+-3498db?style=for-the-badge)](CONFIG.md)

```html
<script src="https://cdn.jsdelivr.net/gh/logiurl/formshield@main/formshield.js"></script>
```

[← Back to README](README.md) · [🚀 Quick Start](README.md#-quick-start) · [🔌 Public API](README.md#-public-api)

<br/>

</div>

---

## Table of Contents

- [Complete Options Object](#complete-options-object)
- [Form Targeting](#1--form-targeting)
- [RSA Encryption](#2--rsa-encryption)
- [Input Sanitization](#3--input-sanitization)
- [Bot Detection](#4--bot-detection)
- [Rate Limiting](#5--rate-limiting)
- [Tamper Detection](#6--tamper-detection)
- [Toast Configuration](#7--toast-configuration)
- [Modal Configuration](#8--modal-configuration)
- [Logging & Reporting](#9--logging--reporting)
- [Callbacks](#10--callbacks)
- [Toast Positions Reference](#toast-positions-reference)
- [Color Tokens Reference](#color-tokens-reference)
- [Preset Configs](#preset-configs)

---

## Complete Options Object

Copy this as your starting point and remove what you don't need:

```js
FormShield.init({

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 1. FORM TARGETING
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  formId:           'loginForm',        // Required — ID of your <form> element
  fieldsToEncrypt:  ['password'],       // Field names to RSA-encrypt before send

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 2. RSA ENCRYPTION
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  enableEncryption: true,
  rsaEndpoint:      '/get-public-key.php',
  rsaFailMode:      'block',            // 'block' | 'warn'

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 3. INPUT SANITIZATION
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  enableSanitization:   true,
  sanitizeMode:         'block',        // 'block' | 'strip'
  maxInputLength:       255,
  customBlockPatterns:  [],             // Array of RegExp or pattern strings

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 4. BOT DETECTION
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  enableBotDetection:     true,
  botSuspicionThreshold:  60,           // 0-100 — score to trigger block
  minSubmitTimeMs:        1800,         // Min milliseconds from render to submit
  honeypotFieldName:      'website',    // Fake field name (should look realistic)

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 5. RATE LIMITING
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  enableRateLimit:     true,
  maxAttempts:         5,               // Attempts before first lockout
  lockoutBaseMinutes:  1,               // First lockout duration (doubles each time)

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 6. TAMPER DETECTION
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  enableTamperDetection: true,
  tamperBlockSubmit:     true,          // Block submit if tampering detected

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 7. TOAST CONFIGURATION
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  toastPosition: 'top-right',
  toastDuration: 4000,
  toastColors: {
    success:      '#2ecc71',
    warning:      '#f39c12',
    error:        '#e74c3c',
    security:     '#8e44ad',
    info:         '#3498db',
    text:         '#ffffff',
    borderRadius: '10px',
    fontSize:     '14px'
  },

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 8. MODAL CONFIGURATION
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  modalColors: {
    overlay:         'rgba(0,0,0,0.7)',
    background:      '#1a1a2e',
    title:           '#e74c3c',
    text:            '#cccccc',
    accent:          '#8e44ad',
    border:          '#e74c3c',
    buttonPrimary:   '#e74c3c',
    buttonSecondary: '#444444'
  },

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 9. LOGGING & REPORTING
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  enableLogging:    true,
  reportEndpoint:   null,               // PHP URL to POST events to (null = disabled)
  reportFormat:     'json',             // 'json' | 'form'
  reportDirectory:  './formshield_logs/',
  reportFilename:   'formshield_log',   // Auto-appends date: formshield_log_2024-01-15.txt
  reportFileFormat: 'txt',             // 'txt' | 'json' | 'csv'
  reportOnEvents:   ['injection', 'bot', 'lockout', 'tamper', 'rsa_fail', 'rate_limit'],
  reportBatchSize:  1,                  // Send after N events (1 = immediate)
  reportAsync:      true,               // Non-blocking fetch (recommended)

  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  // 10. CALLBACKS
  // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  onThreatDetected:   null,   // function(eventObj)
  onBotDetected:      null,   // function(score, signals[])
  onInjectionDetected: null,  // function(fieldName, pattern)
  onLockout:          null,   // function(formId, minutesLocked)
  onEncryptionReady:  null,   // function()
  onSubmitAllowed:    null    // function(formData)

});
```

---

## 1. 🎯 Form Targeting

### `formId`

| Property | Value |
|----------|-------|
| Type | `string` |
| Default | `null` |
| Required | ✅ Yes |

The `id` attribute of the `<form>` element to protect.

```js
FormShield.init({ formId: 'loginForm' });
```

```html
<form id="loginForm" method="POST" action="login.php">...</form>
```

---

### `fieldsToEncrypt`

| Property | Value |
|----------|-------|
| Type | `string[]` |
| Default | `['password']` |
| Required | No |

Array of field `name` attributes to RSA-encrypt before submission. Only applies when `enableEncryption: true`.

```js
// Encrypt a single password field
fieldsToEncrypt: ['password']

// Encrypt multiple sensitive fields
fieldsToEncrypt: ['password', 'confirm_password', 'pin', 'secret_answer']
```

---

## 2. 🔑 RSA Encryption

### `enableEncryption`

| Property | Value |
|----------|-------|
| Type | `boolean` |
| Default | `true` |

Enable RSA-OAEP + SHA-256 encryption of password fields via the **Web Crypto API**.

```js
enableEncryption: true   // Encrypts passwords before send
enableEncryption: false  // Skips encryption entirely
```

---

### `rsaEndpoint`

| Property | Value |
|----------|-------|
| Type | `string` |
| Default | `'/get-public-key.php'` |

URL of the PHP endpoint that returns your RSA public key as JSON.

**Expected response format:**
```json
{ "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----" }
```

Also accepts: `{ "public_key": "..." }` or `{ "key": "..." }`

```js
rsaEndpoint: '/api/get-public-key.php'
rsaEndpoint: 'https://api.yoursite.com/rsa/public-key'
```

---

### `rsaFailMode`

| Property | Value |
|----------|-------|
| Type | `'block'` \| `'warn'` |
| Default | `'block'` |

Behavior when the public key fetch fails (network error, bad response, etc.).

```js
rsaFailMode: 'block'  // Block all submissions — secure, recommended for login forms
rsaFailMode: 'warn'   // Show warning toast, allow unencrypted submission
```

---

## 3. 🧹 Input Sanitization

### `enableSanitization`

| Property | Value |
|----------|-------|
| Type | `boolean` |
| Default | `true` |

Scan all form inputs for injection attacks before submission.

---

### `sanitizeMode`

| Property | Value |
|----------|-------|
| Type | `'block'` \| `'strip'` |
| Default | `'block'` |

```js
sanitizeMode: 'block'  // Stop submission, show modal, log event
sanitizeMode: 'strip'  // Remove bad chars silently, continue submission
```

> Use `'block'` for login/sensitive forms. Use `'strip'` for comment fields where partial input is acceptable.

---

### `maxInputLength`

| Property | Value |
|----------|-------|
| Type | `number` |
| Default | `255` |

Maximum allowed character length per input field.

```js
maxInputLength: 255    // Standard fields
maxInputLength: 72     // Password fields (bcrypt limit)
maxInputLength: 2000   // Textarea / message fields
```

---

### `customBlockPatterns`

| Property | Value |
|----------|-------|
| Type | `(RegExp | string)[]` |
| Default | `[]` |

Additional patterns to block, checked after built-in patterns.

```js
customBlockPatterns: [
  /\b(spam|casino|viagra)\b/i,    // Block spam keywords
  /https?:\/\//i,                 // Block URLs in username fields
  /@(tempmail|throwaway)\.com/i,  // Block disposable emails
  'CUSTOM_KEYWORD'                // String patterns also accepted
]
```

---

## 4. 🤖 Bot Detection

### `enableBotDetection`

| Property | Value |
|----------|-------|
| Type | `boolean` |
| Default | `true` |

Enable the full bot detection stack (honeypot + timing + behavioral entropy).

---

### `botSuspicionThreshold`

| Property | Value |
|----------|-------|
| Type | `number` (0–100) |
| Default | `60` |

Suspicion score required to trigger a bot block. Lower = more strict, higher = more lenient.

```js
botSuspicionThreshold: 40   // Strict — flag most automated attempts
botSuspicionThreshold: 60   // Balanced — default
botSuspicionThreshold: 80   // Lenient — only block obvious bots
botSuspicionThreshold: 100  // Disabled effectively (only honeypot triggers)
```

**Score breakdown:**

| Signal | Score Added |
|--------|------------|
| Honeypot filled | +100 |
| Submit < `minSubmitTimeMs` | +40 |
| No interaction detected | +25 |
| No mouse + no keyboard | +30 |
| No keyboard only | +10 |
| Fields filled < 300ms each | +10/field (max +30) |

---

### `minSubmitTimeMs`

| Property | Value |
|----------|-------|
| Type | `number` |
| Default | `1800` |

Minimum milliseconds from page render to form submission. Submissions faster than this add +40 to the bot score.

```js
minSubmitTimeMs: 1800   // 1.8 seconds — default
minSubmitTimeMs: 3000   // 3 seconds — stricter
minSubmitTimeMs: 800    // 0.8 seconds — lenient
```

---

### `honeypotFieldName`

| Property | Value |
|----------|-------|
| Type | `string` |
| Default | `'website'` |

Name attribute for the hidden honeypot field. Should sound like a real field to fool bots.

```js
honeypotFieldName: 'website'       // Default — most bots will fill this
honeypotFieldName: 'phone_number'  // Alternative realistic name
honeypotFieldName: 'fax'           // Also works well
honeypotFieldName: 'company_name'  // For registration forms
```

> The field is styled with `position:absolute; left:-9999px` and `aria-hidden="true"`. Humans never see it; bots always fill it.

---

## 5. 🔒 Rate Limiting

### `enableRateLimit`

| Property | Value |
|----------|-------|
| Type | `boolean` |
| Default | `true` |

Track failed/blocked attempts in `localStorage` and apply exponential backoff lockouts.

---

### `maxAttempts`

| Property | Value |
|----------|-------|
| Type | `number` |
| Default | `5` |

Number of blocked/failed attempts before the first lockout is applied.

```js
maxAttempts: 3   // Strict — lock after 3 bad attempts
maxAttempts: 5   // Default
maxAttempts: 10  // Lenient — for low-security forms
```

---

### `lockoutBaseMinutes`

| Property | Value |
|----------|-------|
| Type | `number` |
| Default | `1` |

Duration (in minutes) of the first lockout. Each subsequent lockout doubles.

```js
lockoutBaseMinutes: 1   // 1 → 2 → 4 → 8 → 16 min (default)
lockoutBaseMinutes: 5   // 5 → 10 → 20 → 40 min (strict)
lockoutBaseMinutes: 0.5 // 30s → 1m → 2m → 4m (lenient)
```

**Lockout schedule with default settings (`maxAttempts: 5, lockoutBaseMinutes: 1`):**

| Lockout # | Duration | Trigger (cumulative attempts) |
|-----------|----------|-------------------------------|
| 1st | 1 minute | 5 attempts |
| 2nd | 2 minutes | 10 attempts |
| 3rd | 4 minutes | 15 attempts |
| 4th | 8 minutes | 20 attempts |
| 5th | 16 minutes | 25 attempts |

---

## 6. 👁️ Tamper Detection

### `enableTamperDetection`

| Property | Value |
|----------|-------|
| Type | `boolean` |
| Default | `true` |

Take a structural snapshot of the form on init and monitor for DOM changes via `MutationObserver`.

---

### `tamperBlockSubmit`

| Property | Value |
|----------|-------|
| Type | `boolean` |
| Default | `true` |

If tampering is detected, block the submission entirely. Set to `false` to log and warn only.

```js
tamperBlockSubmit: true   // Block submission on tamper (recommended)
tamperBlockSubmit: false  // Log + warn only, allow submission
```

---

## 7. 🔔 Toast Configuration

### `toastPosition`

| Property | Value |
|----------|-------|
| Type | `string` |
| Default | `'top-right'` |

Position of the toast notification container on screen.

```js
toastPosition: 'top-right'     // ↗ Default
toastPosition: 'top-left'      // ↖
toastPosition: 'top-center'    // ↑ Centered
toastPosition: 'bottom-right'  // ↘
toastPosition: 'bottom-left'   // ↙
```

---

### `toastDuration`

| Property | Value |
|----------|-------|
| Type | `number` |
| Default | `4000` |

Auto-dismiss time in milliseconds. Use `0` for persistent toasts that require manual dismissal.

```js
toastDuration: 4000    // 4 seconds — default
toastDuration: 6000    // 6 seconds
toastDuration: 0       // Persistent — must click × to close
```

---

### `toastColors`

All toast color properties are optional. Unset properties fall back to defaults.

```js
toastColors: {
  success:      '#2ecc71',   // ✓ Success toast background
  warning:      '#f39c12',   // ⚠ Warning toast background
  error:        '#e74c3c',   // ✕ Error toast background
  security:     '#8e44ad',   // 🛡 Security toast background
  info:         '#3498db',   // ℹ Info toast background
  text:         '#ffffff',   // All toast text color
  borderRadius: '10px',      // Toast corner radius
  fontSize:     '14px'       // Toast font size
}
```

**Per-toast color override at call time:**

```js
FormShield.toast.error('Something went wrong', {
  duration: 8000,
  backgroundColor: '#c0392b'  // Override just this toast's color
});
```

---

## 8. 🪟 Modal Configuration

### `modalColors`

All modal color properties are optional. Unset properties fall back to defaults.

```js
modalColors: {
  overlay:         'rgba(0,0,0,0.7)',  // Backdrop overlay color
  background:      '#1a1a2e',          // Modal box background
  title:           '#e74c3c',          // Modal title text
  text:            '#cccccc',          // Modal description text
  accent:          '#8e44ad',          // Threat detail box text + border
  border:          '#e74c3c',          // Modal outer border
  buttonPrimary:   '#e74c3c',          // "Dismiss" button background
  buttonSecondary: '#444444'           // "Report & Dismiss" button background
}
```

**Modal types automatically used:**

| Modal | Trigger | Default Icon |
|-------|---------|-------------|
| `InjectionModal` | SQL/XSS/traversal detected | ⚠ |
| `BotModal` | Bot score exceeds threshold | 🤖 |
| `LockoutModal` | Rate limit lockout applied | 🔒 |
| `TamperModal` | Form DOM modified after init | ⚠ |

---

## 9. 📋 Logging & Reporting

### `enableLogging`

| Property | Value |
|----------|-------|
| Type | `boolean` |
| Default | `true` |

Maintain an in-memory event log for the current session. Required for `getLogs()` and `exportLogs()`.

---

### `reportEndpoint`

| Property | Value |
|----------|-------|
| Type | `string` \| `null` |
| Default | `null` |

URL of your PHP logging endpoint. Set to `null` to disable server-side reporting.

```js
reportEndpoint: null                               // No server reporting (default)
reportEndpoint: '/api/formshield-logger.php'       // Relative URL
reportEndpoint: 'https://mysite.com/logger.php'   // Absolute URL
```

---

### `reportFormat`

| Property | Value |
|----------|-------|
| Type | `'json'` \| `'form'` |
| Default | `'json'` |

HTTP request body format for reporting.

```js
reportFormat: 'json'   // Content-Type: application/json (default, recommended)
reportFormat: 'form'   // Content-Type: application/x-www-form-urlencoded
```

---

### `reportDirectory`

| Property | Value |
|----------|-------|
| Type | `string` |
| Default | `'./formshield_logs/'` |

Directory path sent to PHP so it knows where to write the log files. Relative to your PHP script.

```js
reportDirectory: './formshield_logs/'      // Default
reportDirectory: '../logs/security/'       // Parent directory
reportDirectory: '/var/log/formshield/'    // Absolute path (ensure PHP has write access)
```

---

### `reportFilename`

| Property | Value |
|----------|-------|
| Type | `string` |
| Default | `'formshield_log'` |

Base filename for log files. The date is auto-appended: `formshield_log_2024-01-15.txt`

```js
reportFilename: 'formshield_log'     // → formshield_log_2024-01-15.txt
reportFilename: 'security_events'    // → security_events_2024-01-15.txt
reportFilename: 'login_threats'      // → login_threats_2024-01-15.txt
```

---

### `reportFileFormat`

| Property | Value |
|----------|-------|
| Type | `'txt'` \| `'json'` \| `'csv'` |
| Default | `'txt'` |

File extension and format for server-side log files.

```js
reportFileFormat: 'txt'    // Plain text, one entry per line
reportFileFormat: 'json'   // JSON entries appended per line
reportFileFormat: 'csv'    // Comma-separated values
```

---

### `reportOnEvents`

| Property | Value |
|----------|-------|
| Type | `string[]` |
| Default | `['injection','bot','lockout','tamper','rsa_fail','rate_limit']` |

Filter which event types are sent to the server endpoint.

```js
// Report all events (default)
reportOnEvents: ['injection', 'bot', 'lockout', 'tamper', 'rsa_fail', 'rate_limit']

// Only report high-severity events
reportOnEvents: ['injection', 'bot', 'tamper']

// Only report lockouts
reportOnEvents: ['lockout']
```

---

### `reportAsync`

| Property | Value |
|----------|-------|
| Type | `boolean` |
| Default | `true` |

```js
reportAsync: true    // Non-blocking fetch — page continues normally (recommended)
reportAsync: false   // Synchronous XHR — blocks until response (use only for testing)
```

---

## 10. 📣 Callbacks

All callbacks are optional. Set to `null` to disable.

### `onThreatDetected`

Called for any security event that triggers a block. Receives a unified event object.

```js
onThreatDetected: function(event) {
  // event.type: 'injection' | 'bot' | 'lockout' | 'tamper' | 'rate_limit'
  console.warn('Threat detected:', event.type, event);

  // Example: send to your own analytics
  myAnalytics.track('security_threat', {
    type:   event.type,
    formId: event.formId,
    detail: event.detail
  });
}
```

---

### `onBotDetected`

```js
onBotDetected: function(score, signals) {
  // score: number (0-100)
  // signals: string[] e.g. ['submit_too_fast (420ms)', 'no_mouse_or_keyboard']
  console.warn('Bot score:', score, 'Signals:', signals);
}
```

---

### `onInjectionDetected`

```js
onInjectionDetected: function(fieldName, pattern) {
  // fieldName: 'username' | 'email' | etc.
  // pattern: the regex pattern string that matched
  console.warn('Injection in field:', fieldName, 'Pattern:', pattern);
}
```

---

### `onLockout`

```js
onLockout: function(formId, minutesLocked) {
  // formId: string
  // minutesLocked: number
  console.warn('Lockout on', formId, 'for', minutesLocked, 'minutes');

  // Example: notify your server
  fetch('/api/lockout-alert', {
    method: 'POST',
    body: JSON.stringify({ form: formId, minutes: minutesLocked })
  });
}
```

---

### `onEncryptionReady`

```js
onEncryptionReady: function() {
  // RSA public key loaded and ready
  // Show a "🔒 Secure" indicator to the user
  document.getElementById('secure-badge').style.display = 'block';
}
```

---

### `onSubmitAllowed`

```js
onSubmitAllowed: function(formData) {
  // Called just before a clean submission is sent
  // formData: FormData object (read-only reference)
  console.log('[FormShield] Clean submission approved');

  // Example: add a submission token
  // (modifying formEl before returning also works)
}
```

---

## Toast Positions Reference

```
┌─────────────────────────────────────────────────────────┐
│  top-left             top-center             top-right  │
│  ┌───────┐            ┌───────┐              ┌───────┐  │
│  │ Toast │            │ Toast │              │ Toast │  │
│  └───────┘            └───────┘              └───────┘  │
│                                                          │
│                                                          │
│  ┌───────┐                                  ┌───────┐  │
│  │ Toast │                                  │ Toast │  │
│  └───────┘                                  └───────┘  │
│  bottom-left                              bottom-right  │
└─────────────────────────────────────────────────────────┘
```

---

## Color Tokens Reference

### Toast Color Tokens

| Token | Applies To | Default |
|-------|-----------|---------|
| `success` | ✓ Success toast background | `#2ecc71` |
| `warning` | ⚠ Warning toast background | `#f39c12` |
| `error` | ✕ Error toast background | `#e74c3c` |
| `security` | 🛡 Security toast background | `#8e44ad` |
| `info` | ℹ Info toast background | `#3498db` |
| `text` | All toast text | `#ffffff` |
| `borderRadius` | Toast corner roundness | `10px` |
| `fontSize` | Toast text size | `14px` |

### Modal Color Tokens

| Token | Applies To | Default |
|-------|-----------|---------|
| `overlay` | Backdrop blur overlay | `rgba(0,0,0,0.7)` |
| `background` | Modal box background | `#1a1a2e` |
| `title` | Modal title text | `#e74c3c` |
| `text` | Modal description text | `#cccccc` |
| `accent` | Threat detail box text + border | `#8e44ad` |
| `border` | Modal outer border | `#e74c3c` |
| `buttonPrimary` | "Dismiss" button | `#e74c3c` |
| `buttonSecondary` | "Report & Dismiss" button | `#444444` |

---

## Preset Configs

Copy-paste ready configurations for common use cases:

### 🏦 High-Security Login Form

```js
FormShield.init({
  formId:                'loginForm',
  fieldsToEncrypt:       ['password'],
  enableEncryption:      true,
  rsaEndpoint:           '/api/get-public-key.php',
  rsaFailMode:           'block',
  sanitizeMode:          'block',
  maxInputLength:        72,
  enableBotDetection:    true,
  botSuspicionThreshold: 40,
  minSubmitTimeMs:       2500,
  enableRateLimit:       true,
  maxAttempts:           3,
  lockoutBaseMinutes:    5,
  enableTamperDetection: true,
  tamperBlockSubmit:     true,
  reportEndpoint:        '/api/formshield-logger.php',
  reportOnEvents:        ['injection', 'bot', 'lockout', 'tamper', 'rsa_fail'],
  toastPosition:         'top-right',
  toastDuration:         5000
});
```

---

### 📩 Contact / Feedback Form

```js
FormShield.init({
  formId:                'contactForm',
  enableEncryption:      false,
  sanitizeMode:          'strip',
  maxInputLength:        1000,
  enableBotDetection:    true,
  botSuspicionThreshold: 70,
  minSubmitTimeMs:       1500,
  enableRateLimit:       true,
  maxAttempts:           10,
  lockoutBaseMinutes:    1,
  enableTamperDetection: false,
  reportEndpoint:        null,
  toastPosition:         'bottom-right',
  toastDuration:         3000
});
```

---

### 📝 Registration Form

```js
FormShield.init({
  formId:                'registerForm',
  fieldsToEncrypt:       ['password', 'confirm_password'],
  enableEncryption:      true,
  rsaEndpoint:           '/api/get-public-key.php',
  rsaFailMode:           'warn',
  sanitizeMode:          'block',
  maxInputLength:        255,
  customBlockPatterns:   [/@(tempmail|guerrilla|throwaway)\./i],
  enableBotDetection:    true,
  botSuspicionThreshold: 55,
  minSubmitTimeMs:       2000,
  enableRateLimit:       true,
  maxAttempts:           5,
  lockoutBaseMinutes:    2,
  enableTamperDetection: true,
  tamperBlockSubmit:     true,
  reportEndpoint:        '/api/formshield-logger.php',
  toastPosition:         'top-center'
});
```

---

### 🚀 Minimal / No Encryption (Static Sites)

```js
FormShield.init({
  formId:                'searchForm',
  enableEncryption:      false,
  sanitizeMode:          'block',
  maxInputLength:        200,
  enableBotDetection:    true,
  botSuspicionThreshold: 75,
  enableRateLimit:       false,
  enableTamperDetection: false,
  enableLogging:         false,
  reportEndpoint:        null,
  toastPosition:         'top-right',
  toastDuration:         3000
});
```

---

### 🔇 Silent Mode (No Modals / No Toasts Except Callbacks)

```js
// Use this if you want to handle all UI yourself via callbacks
FormShield.init({
  formId:                'myForm',
  enableEncryption:      true,
  rsaEndpoint:           '/api/key.php',
  rsaFailMode:           'block',
  sanitizeMode:          'block',
  enableBotDetection:    true,
  enableRateLimit:       true,
  enableTamperDetection: true,
  toastDuration:         0,   // Setting custom handlers below

  onThreatDetected: function(event) {
    myUI.showCustomAlert({
      title: 'Security Alert',
      body:  'Blocked: ' + event.type,
      data:  event
    });
  },
  onBotDetected: function(score, signals) {
    myUI.showCustomAlert({ title: 'Bot Detected', body: 'Score: ' + score });
  },
  onInjectionDetected: function(fieldName, pattern) {
    myUI.highlightField(fieldName, 'Suspicious content detected');
  }
});
```

---

<div align="center">

[![CDN](https://img.shields.io/badge/CDN-jsDelivr-orange?style=flat-square&logo=jsdelivr)](https://cdn.jsdelivr.net/gh/logiurl/formshield@main/formshield.js)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ecc71?style=flat-square)](LICENSE)
[![Free to Use](https://img.shields.io/badge/free_to_use-✓-2ecc71?style=flat-square)](https://cdn.jsdelivr.net/gh/logiurl/formshield@main/formshield.js)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square)](https://cdn.jsdelivr.net/gh/logiurl/formshield@main/formshield.js)

[← Back to README](README.md) · [🔝 Back to Top](#️-formshieldjs--configuration-reference)

</div>
