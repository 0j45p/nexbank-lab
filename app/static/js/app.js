/* NexBank Digital — frontend JS
 * Lab 5: AES key/IV hardcoded here — visible to anyone who opens DevTools → Sources
 * Lab 7: IDOR visible — getUserProfile(userId) calls /api/account/{userId}/profile without ownership check
 */

const NEXBANK_AES_KEY = "NexBankSecure2024";
const NEXBANK_AES_IV  = "1234567890123456";
const NEXBANK_API_KEY = "nb-internal-api-key-dev-2024";   // Lab extra: key in JS source

/* ── AES helpers (CryptoJS) ─────────────────────────────────────────────────── */

function aesEncrypt(plaintext) {
  // Key padding MUST match the backend's Python `.encode().ljust(32)[:32]`,
  // which pads with spaces (0x20) — not '\0'. A mismatch here silently
  // produces a different 32-byte key on each side and every decrypt fails
  // with a PKCS7 padding error.
  var key    = CryptoJS.enc.Utf8.parse(NEXBANK_AES_KEY.padEnd(32, ' ').slice(0, 32));
  var iv     = CryptoJS.enc.Utf8.parse(NEXBANK_AES_IV.padEnd(16, '\0').slice(0, 16));
  var enc    = CryptoJS.AES.encrypt(plaintext, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  return enc.toString();   // Base64
}

function aesDecrypt(ciphertextBase64) {
  var key  = CryptoJS.enc.Utf8.parse(NEXBANK_AES_KEY.padEnd(32, ' ').slice(0, 32));
  var iv   = CryptoJS.enc.Utf8.parse(NEXBANK_AES_IV.padEnd(16, '\0').slice(0, 16));
  var dec  = CryptoJS.AES.decrypt(ciphertextBase64, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  return dec.toString(CryptoJS.enc.Utf8);
}

/* ── Auth helpers ────────────────────────────────────────────────────────────── */

function getToken() {
  return localStorage.getItem('nexbank_token') || getCookie('auth_token');
}

function getCookie(name) {
  var m = document.cookie.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}

function authHeaders() {
  var tok = getToken();
  return tok ? { 'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json' } : { 'Content-Type': 'application/json' };
}

/* ── Transfer (Lab 5) ────────────────────────────────────────────────────────── */

function submitTransfer(fromAcct, toAcct, amount, description) {
  var payload    = JSON.stringify({ from_account: fromAcct, to_account: toAcct, amount: parseFloat(amount), description: description });
  var encPayload = aesEncrypt(payload);

  document.getElementById('enc-payload-display') && (document.getElementById('enc-payload-display').textContent = encPayload);

  return fetch('/api/txn/transfer', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ enc_payload: encPayload })
  }).then(function(r) { return r.json(); });
}

/* ── IDOR helpers (Lab 7) ────────────────────────────────────────────────────── */

function getUserProfile(userId) {
  // Lab 7: no ownership check — any userId works
  return fetch('/api/account/user/' + userId + '/profile', { headers: authHeaders() })
    .then(function(r) { return r.json(); });
}

function getAccountDetails(accountId) {
  return fetch('/api/account/' + accountId, { headers: authHeaders() })
    .then(function(r) { return r.json(); });
}

function getTransaction(txnId) {
  return fetch('/api/txn/' + txnId, { headers: authHeaders() })
    .then(function(r) { return r.json(); });
}

/* ── JWT inspector ────────────────────────────────────────────────────────────── */

function decodeJWT(token) {
  try {
    var parts = token.split('.');
    if (parts.length < 2) return null;
    var payload = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(payload);
  } catch (e) { return null; }
}

/* ── OTP helpers (Lab 1) ─────────────────────────────────────────────────────── */

function sendOTP(mobile) {
  return fetch('/api/auth/send-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mobile: mobile })
  }).then(function(r) {
    // Lab 1 hint: check response headers for X-Debug-OTP
    console.log('[NexBank] X-Debug-OTP:', r.headers.get('X-Debug-OTP'));
    return r.json();
  });
}

function verifyOTP(mobile, otp, bypass) {
  // AES-CBC encrypt the OTP payload before sending.
  // Key: NEXBANK_AES_KEY (this file, line 6). IV: NEXBANK_AES_IV (line 7).
  // Anyone who reads this source has the key and can decrypt or forge any OTP request.
  if (bypass) {
    // bypass param is sent plaintext so the Lab 1 flaw still works
    return fetch('/api/auth/verify-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mobile: mobile, otp_bypass: true })
    }).then(function(r) { return r.json(); });
  }
  var plaintext  = JSON.stringify({ mobile: mobile, otp: otp });
  var encPayload = aesEncrypt(plaintext);
  return fetch('/api/auth/verify-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enc_payload: encPayload })
  }).then(function(r) { return r.json(); });
}

/* ── Notification helper ─────────────────────────────────────────────────────── */

function showAlert(msg, type) {
  type = type || 'info';
  var el = document.getElementById('alert-box');
  if (!el) return;
  el.className = 'alert alert-' + type;
  el.textContent = msg;
  el.style.display = 'block';
  setTimeout(function() { el.style.display = 'none'; }, 4000);
}
