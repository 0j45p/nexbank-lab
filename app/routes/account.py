"""
Account Routes
Lab 7:  IDOR — no ownership check on user profile / account / balance
Lab 6:  Mass Assignment — any field including role/kyc_status/is_verified can be overwritten
Lab 10: Path Traversal — statement download joins an unsanitized filename onto disk
Lab 11: SSRF — receipt PDF generation fetches an attacker-supplied logo URL server-side
Lab 15: Privilege Escalation — self-service role upgrade applies immediately
with no approval workflow and no allow-list (see request_role_upgrade() below).
"""
import base64, json, os
from io import BytesIO

import requests
from fpdf import FPDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from flask import Blueprint, request, jsonify, g, current_app, send_file
from app import db
from models.user import User
from models.account import BankAccount
from routes.auth import require_auth

account_bp = Blueprint('account', __name__)

# Lab 10: statements live outside static/ — only reachable through the
# (vulnerable) download endpoint below, not directly over HTTP.
STATEMENTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'statements')


def _aes_decrypt(ciphertext_b64: str) -> str:
    """Same AES-256-CBC config used everywhere in this app (Lab 5) — key/IV
    live in both config.py (server) and static/js/app.js (client), so anyone
    who reads either can decrypt (or forge) any enc_payload, e.g. with
    tools/burp_nexbank_decryptor.py."""
    key = current_app.config['AES_KEY'].encode().ljust(32)[:32]
    iv  = current_app.config['AES_IV'].encode().ljust(16)[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = base64.b64decode(ciphertext_b64)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# Fields that should NOT be updatable — but the code allows them anyway
ALLOWED_FOR_MASS_ASSIGN = [
    'name', 'email', 'mobile',
    'role', 'is_verified', 'kyc_status',    # privileged — should be admin-only
    'pan_number', 'aadhaar_number',
]


# ── Lab 7: IDOR ────────────────────────────────────────────────────────────────

@account_bp.route('/user/<int:user_id>/profile', methods=['GET'])
@require_auth
def get_user_profile(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify({'user': user.to_dict(include_sensitive=True)}), 200


@account_bp.route('/<int:account_id>', methods=['GET'])
@require_auth
def get_account_details(account_id):
    acct = BankAccount.query.get_or_404(account_id)
    d = acct.to_dict()
    owner = User.query.get(acct.user_id)
    if owner:
        d['owner_name']  = owner.name
        d['owner_email'] = owner.email
    return jsonify({'account': d}), 200


@account_bp.route('/all', methods=['GET'])
@require_auth
def list_all_accounts():
    accounts = BankAccount.query.all()
    result = []
    for a in accounts:
        d = a.to_dict()
        owner = User.query.get(a.user_id)
        if owner:
            d['owner_name'] = owner.name
        result.append(d)
    return jsonify({'accounts': result, 'total': len(result)}), 200


@account_bp.route('/my-accounts', methods=['GET'])
@require_auth
def my_accounts():
    accounts = BankAccount.query.filter_by(user_id=g.current_user.id).all()
    return jsonify({'accounts': [a.to_dict() for a in accounts]}), 200


# ── Mass Assignment ────────────────────────────────────────────────────────────

@account_bp.route('/profile', methods=['PUT'])
@require_auth
def update_profile():
    data = request.get_json() or {}

    # Client-side AES-CBC encryption: frontend encrypts profile fields before PUT.
    # Key is hardcoded in /static/js/app.js — trivially recoverable from browser source.
    enc_payload = data.get('enc_payload')
    if enc_payload:
        try:
            key = current_app.config['AES_KEY'].encode().ljust(32)[:32]
            iv  = current_app.config['AES_IV'].encode().ljust(16)[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ct = base64.b64decode(enc_payload)
            data = json.loads(unpad(cipher.decrypt(ct), AES.block_size).decode())
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {e}', 'hint': 'Key is in /static/js/app.js'}), 400

    user = g.current_user
    updated = []
    for field in ALLOWED_FOR_MASS_ASSIGN:
        if field in data:
            setattr(user, field, data[field])
            updated.append(field)
    db.session.commit()
    return jsonify({
        'message': 'Profile updated',
        'updated_fields': updated,
        'user': user.to_dict(include_sensitive=True),
    }), 200


@account_bp.route('/balance/<int:account_id>', methods=['GET'])
@require_auth
def get_balance(account_id):
    acct = BankAccount.query.get_or_404(account_id)
    return jsonify({'account_number': acct.account_number, 'balance': float(acct.balance)}), 200


# ── Lab 10: Path Traversal ──────────────────────────────────────────────────────

@account_bp.route('/statement/download', methods=['GET'])
@require_auth
def download_statement():
    """`file` is joined onto STATEMENTS_DIR and normalized, but never checked
    to still be inside STATEMENTS_DIR afterwards — normpath cleans up '../'
    sequences, it doesn't block them, and os.path.join() silently discards
    STATEMENTS_DIR entirely if `file` is an absolute path. Classic payloads:

      ?file=/etc/passwd                     (or ../../../../etc/passwd)
      ?file=C:\\Windows\\win.ini             (Windows host)

    Also walks into this app's own tree for a stronger PoC:

      ?file=../config.py   → leaks AES_KEY, JWT_SECRET, RESET_TOKEN_SALT

    Like everywhere else in the app, `file` can also arrive AES-encrypted as
    ?enc_payload=<base64 ciphertext of {"file": "..."}> — same key/IV as Lab
    5, decryptable with tools/burp_nexbank_decryptor.py. Plaintext ?file=
    still works too, for quick testing via Swagger.
    """
    enc_payload = request.args.get('enc_payload')
    if enc_payload:
        try:
            filename = json.loads(_aes_decrypt(enc_payload)).get('file', 'statement_sample.txt')
        except Exception as e:
            return jsonify({'error': 'Decryption failed: %s' % str(e)}), 400
    else:
        filename = request.args.get('file', 'statement_sample.txt')
    path = os.path.normpath(os.path.join(STATEMENTS_DIR, filename))
    if not os.path.exists(path) or os.path.isdir(path):
        return jsonify({'error': 'File not found', 'path_checked': path}), 404
    return send_file(path, as_attachment=True, download_name=os.path.basename(filename))


# ── Lab 11: SSRF (via PDF generation) ────────────────────────────────────────

def _fetch_logo_source(logo_url):
    """Resolves `logo_url` to (content_bytes, content_type, status_line).
    Handles http(s):// via a real server-side request (the SSRF) AND
    file:// by reading straight off local disk with no path restriction at
    all — the same scheme is never validated, so this single parameter
    escalates from SSRF (reach internal services) to full local file read
    (reach anything the app process can open), exactly like the many real
    SSRF-to-LFI CVEs caused by URL-fetching code that never checks the
    scheme before handing the target to a file:// -capable client."""
    if logo_url.startswith('file://'):
        local_path = logo_url[len('file://'):]
        with open(local_path, 'rb') as f:
            content = f.read()
        return content, 'text/plain', '200 (local file)'

    resp = requests.get(logo_url, timeout=5)
    return resp.content, resp.headers.get('Content-Type', ''), str(resp.status_code)


@account_bp.route('/receipt/download', methods=['GET'])
@require_auth
def receipt_download():
    """Generates a downloadable transaction-receipt PDF. The bank letterhead
    logo is fetched server-side from an attacker-supplied `logo_url` and
    embedded into the PDF — the same bug class as real wkhtmltopdf/headless-
    Chrome PDF pipelines that fetch attacker-controlled <img src> URLs during
    rendering. No allow-list, no scheme restriction, no block on internal or
    link-local address ranges — and see _fetch_logo_source() above for how
    that same missing scheme check escalates straight into path traversal.

    Classic PoCs:
      ?logo_url=http://redis:6379/                          (SSRF — internal-only, never proxied by nginx)
      ?logo_url=http://app:5000/debug/config                (SSRF — leaks JWT_SECRET/AES_KEY/DB creds)
      ?logo_url=http://169.254.169.254/latest/meta-data/     (SSRF — real cloud infra)
      ?logo_url=file:///etc/passwd                           (LFI — Linux/docker)
      ?logo_url=file://C:/Windows/win.ini                    (LFI — Windows host)
      ?logo_url=file:///app/config.py                        (LFI — leaks this app's own secrets, docker WORKDIR is /app)

    When the fetched resource isn't a valid image, its raw content gets
    printed directly onto the PDF page instead — so the result is always
    visible in the generated file, not blind.

    Also accepts ?enc_payload=<base64 ciphertext of {"logo_url":"...","txn_id":"..."}>
    — same AES-256-CBC key/IV as the rest of the app."""
    enc_payload = request.args.get('enc_payload')
    if enc_payload:
        try:
            params = json.loads(_aes_decrypt(enc_payload))
        except Exception as e:
            return jsonify({'error': 'Decryption failed: %s' % str(e)}), 400
        logo_url = params.get('logo_url', '')
        txn_id   = params.get('txn_id', 'N/A')
    else:
        logo_url = request.args.get('logo_url', '')
        txn_id   = request.args.get('txn_id', 'N/A')

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 10, 'NexBank Digital - Transaction Receipt', ln=True)
    pdf.set_font('Helvetica', '', 11)
    pdf.cell(0, 8, 'Account holder: %s' % g.current_user.name, ln=True)
    pdf.cell(0, 8, 'Transaction ID: %s' % txn_id, ln=True)
    pdf.ln(6)

    if logo_url:
        try:
            content, ctype, status = _fetch_logo_source(logo_url)
            embedded_as_image = False
            if 'image' in ctype:
                try:
                    pdf.image(BytesIO(content), x=150, y=10, w=40)
                    embedded_as_image = True
                except Exception:
                    embedded_as_image = False
            if not embedded_as_image:
                # Not a renderable image — dump whatever we fetched/read
                # straight onto the receipt so the impact is visible on the page.
                pdf.set_font('Courier', '', 8)
                try:
                    preview = content.decode('utf-8', 'replace')[:1500]
                except Exception:
                    preview = base64.b64encode(content[:500]).decode()
                pdf.multi_cell(0, 4, 'Letterhead source: %s -> %s (%s)\n%s' % (
                    logo_url, status, ctype or 'unknown', preview))
        except Exception as e:
            pdf.set_font('Helvetica', 'I', 9)
            pdf.multi_cell(0, 8, 'Letterhead fetch failed for %s: %s' % (logo_url, str(e)))

    buf = BytesIO(bytes(pdf.output()))
    buf.seek(0)
    return send_file(buf, mimetype='application/pdf', as_attachment=True,
                      download_name='NexBank_Receipt_%s.pdf' % txn_id)


# ── Lab 15: Privilege Escalation ─────────────────────────────────────────────

# Tiers a customer is legitimately allowed to self-request. Never actually
# enforced below — documents intent only, which is exactly the bug.
REQUESTABLE_TIERS = ['basic', 'premium', 'corporate', 'nri']


@account_bp.route('/request-role-upgrade', methods=['POST'])
@require_auth
def request_role_upgrade():
    """Self-service account-tier upgrade ('basic' -> 'premium'/'corporate'/'nri'),
    modeled on real net-banking "upgrade my account" flows. VULNERABILITY: the
    requested value is applied immediately with no approval workflow and no
    check against REQUESTABLE_TIERS above — requesting role='admin' works
    exactly the same as requesting a legitimate tier. This is a second,
    independent path to the same outcome as Lab 6's mass-assignment bug
    (PUT /api/account/profile {"role":"admin"}) and the missing role check on
    PUT /api/admin/users/{id}/role (routes/admin.py — any authenticated user,
    not just admins, can call it).

    Body can be plaintext {"requested_role": "..."} or, like the rest of the
    app, {"enc_payload": "<base64 ciphertext of the same JSON>"}."""
    data = request.get_json() or {}
    enc_payload = data.get('enc_payload')
    if enc_payload:
        try:
            data = json.loads(_aes_decrypt(enc_payload))
        except Exception as e:
            return jsonify({'error': 'Decryption failed: %s' % str(e)}), 400
    requested_role = data.get('requested_role', '')
    if not requested_role:
        return jsonify({'error': 'requested_role required', 'valid_tiers': REQUESTABLE_TIERS}), 400

    user = g.current_user
    old_role = user.role
    user.role = requested_role
    db.session.commit()

    return jsonify({
        'message': 'Role upgrade approved automatically — no manual review required',
        'old_role': old_role,
        'new_role': user.role,
    }), 200
