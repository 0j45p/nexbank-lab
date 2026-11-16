# NexBank Digital — Auth & Crypto Vulnerability Lab

**Made by Ojas Patil**
**RedCIPHER Security Training | Deliberately Vulnerable Banking Platform**

> ⚠️ This application contains intentional security vulnerabilities for educational purposes only.
> Do NOT deploy on production or expose to the public internet.

---

## Overview

NexBank Digital is a realistic digital banking portal purpose-built to teach broken authentication, cryptographic failures, IDOR, and account takeover — the exact vulnerability classes found in real-world fintech VAPT engagements.

### Tech Stack

| Component | Technology |
|-----------|------------|
| Backend   | Python Flask |
| Database  | PostgreSQL |
| Sessions  | Redis |
| Proxy     | Nginx |
| Runtime   | Docker Compose |
| Domain    | nexbank.local |

---

## Quick Start

```bash
chmod +x setup.sh
./setup.sh
```

Then open: **http://nexbank.local** (or **http://lab.ojas.hack** — see below)

### Manual Setup

```bash
# Add to /etc/hosts (Linux/macOS)
echo "127.0.0.1  nexbank.local" | sudo tee -a /etc/hosts
echo "127.0.0.1  lab.ojas.hack" | sudo tee -a /etc/hosts

# Start containers
docker-compose up -d --build

# Seed database
docker-compose exec app python -c "from seeds.seed_data import seed_all; seed_all()"
```

### Windows hosts file

Edit `C:\Windows\System32\drivers\etc\hosts` **as Administrator** (Notepad or an
elevated PowerShell — editing this file requires admin rights) and add:

```
127.0.0.1 nexbank.local
127.0.0.1 lab.ojas.hack
```

Each entry must be `IP<space>hostname` on **one line** — splitting them across
two lines, or saving the file in UTF-16 instead of plain ASCII, silently breaks
name resolution (Windows Notepad defaults to UTF-8 now, but double-check "Save
As" encoding if using an older Notepad or a script-based edit).

`nginx.conf`'s `server_name` already accepts `nexbank.local`, `localhost`, and
`lab.ojas.hack` — no other config changes needed once the hosts entry resolves.

---

## Test Users

| Mobile       | Name          | Role     | Password     | MD5 Hash                         |
|--------------|---------------|----------|--------------|----------------------------------|
| 9100000001   | Arjun Mehta   | customer | password123  | 482c811da5d5b4bc6d497ffa98491e38 |
| 9100000002   | Priya Nair    | customer | password123  | 482c811da5d5b4bc6d497ffa98491e38 |
| 9100000003   | Rohan Desai   | customer | password123  | 482c811da5d5b4bc6d497ffa98491e38 |
| 9100000004   | Sneha Kapoor  | customer | password123  | 482c811da5d5b4bc6d497ffa98491e38 |
| 9999999999   | Admin NexBank | admin    | Admin@123    | 3f5e3e9a4f8c0b4b2c2e1f5a6d7e8b9c |

---

## Security Labs

| Lab | Category         | Vulnerability                        | OWASP         |
|-----|-----------------|--------------------------------------|---------------|
| L01 | Broken Auth      | OTP Bypass (header leak, bypass param, rate limit spoof) | A07:2021 |
| L02 | Broken Auth      | Predictable Reset Token + Host Header Injection | A07:2021 |
| L03 | Broken Auth      | Session Fixation (no session regeneration) | A07:2021 |
| L04 | Broken Auth      | 2FA Step-Skip via cookie manipulation | A07:2021 |
| L05 | Crypto Failure   | Hardcoded AES-256 Key in JS Bundle   | A02:2021 |
| L06 | Crypto Failure   | MD5 Password Storage (no salt)        | A02:2021 |
| L07 | Broken Access    | IDOR — Transactions, Accounts, Profiles | A01:2021 |
| L08 | Broken Auth      | JWT alg:none + Weak Secret + Logic Flaw | A07:2021 |
| L09 | XSS              | Stored XSS via transaction description (dashboard + statement) | A03:2021 |
| L10 | Path Traversal   | Statement download — unsanitized `file` param | A01:2021 |
| L11 | SSRF / LFI       | Receipt PDF letterhead fetches attacker-supplied URL server-side; file:// escalates to local file read | A10:2021 |
| L12 | Broken Access    | Hidden admin impersonation endpoint, discoverable only via leaked Swagger | A01:2021 |
| L13 | Vulnerable/Outdated Components | Exposed `package.json` — known-CVE deps + dependency-confusion risk | A06:2021 |
| L14 | XXE | Bulk transfer batch upload — lxml parses XML with entity resolution enabled | A05:2021 |
| L15 | Privilege Escalation | Self-service role upgrade + unguarded admin role-change endpoint both apply any role with no check | A01:2021 |

---

## Key Credentials (Intentionally Exposed)

| Secret | Value |
|--------|-------|
| JWT Secret | `nexbank2024` |
| AES Key | `NexBankSecure2024` |
| AES IV | `1234567890123456` |
| Reset Token Salt | `nexbank_static_salt` |
| DB Password | `nexbank123` |

---

## Important URLs

| URL | Purpose |
|-----|---------|
| http://nexbank.local | Main application |
| http://nexbank.local/login | Login (Labs 1,3,4) |
| http://nexbank.local/forgot-password | Reset (Lab 2) |
| http://nexbank.local/transfer | Transfer (Lab 5) |
| http://nexbank.local/transactions | IDOR (Lab 7) |
| http://nexbank.local/profile | Mass Assignment + IDOR |
| http://nexbank.local/debug | Info disclosure |
| http://nexbank.local/debug/users | All users + MD5 hashes |
| http://nexbank.local/debug/sessions | Active JWT tokens |
| http://nexbank.local/api/docs | Swagger UI (Lab 12) — reveals the hidden impersonate endpoint |
| http://nexbank.local/api/openapi.json | Raw OpenAPI spec (Lab 12) |
| http://nexbank.local/static/package.json | Exposed dependency manifest (Lab 13) |

---

## Common Commands

```bash
docker-compose up -d          # Start
docker-compose down -v        # Stop + wipe data
docker-compose logs -f app    # App logs
docker-compose exec app bash  # Shell into container

# Re-seed
docker-compose exec app python -c "from seeds.seed_data import seed_all; seed_all()"
```

---

## Lab Guide

See [`docs/LAB_GUIDE.md`](docs/LAB_GUIDE.md) for step-by-step exploitation instructions.

---

**Happy Hacking! 🎯 — RedCIPHER Security Training | Made by Ojas Patil**
