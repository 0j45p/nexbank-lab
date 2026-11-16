"""
Transaction Routes
Lab 5:  AES-CBC hardcoded key/IV — key in frontend JS, decrypt_demo exposes it
Lab 7:  IDOR — no ownership check on transaction lookups
Lab 9:  Stored XSS — `description` below is never sanitized and is rendered via
raw innerHTML in dashboard.html / transactions.html. Any authenticated user can
transfer ₹1 to any account (Lab 7 has no restriction on to_account either) with
a malicious description, and it fires in the victim's browser on next login.
Lab 14: XXE — bulk_upload() parses XML with entity resolution enabled, the
classic vulnerable lxml configuration (see routes/txn.py bulk_upload()).
"""
import base64, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from lxml import etree

from flask import Blueprint, request, jsonify, current_app, g
from app import db
from models.account import BankAccount, Transaction
from routes.auth import require_auth

txn_bp = Blueprint('txn', __name__)


def _aes_encrypt(plaintext: str) -> str:
    key = current_app.config['AES_KEY'].encode().ljust(32)[:32]
    iv  = current_app.config['AES_IV'].encode().ljust(16)[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(ct).decode()


def _aes_decrypt(ciphertext_b64: str) -> str:
    key = current_app.config['AES_KEY'].encode().ljust(32)[:32]
    iv  = current_app.config['AES_IV'].encode().ljust(16)[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = base64.b64decode(ciphertext_b64)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()


# ── Lab 7: IDOR ────────────────────────────────────────────────────────────────

@txn_bp.route('/<int:txn_id>', methods=['GET'])
@require_auth
def get_transaction(txn_id):
    txn = Transaction.query.get_or_404(txn_id)
    d = txn.to_dict()
    d['enc_payload'] = txn.enc_payload
    if txn.enc_payload:
        try:
            d['decrypted_payload'] = _aes_decrypt(txn.enc_payload)
        except Exception as e:
            d['decrypt_error'] = str(e)
    return jsonify({'transaction': d}), 200


@txn_bp.route('/all', methods=['GET'])
@require_auth
def all_transactions():
    txns = Transaction.query.order_by(Transaction.created_at.desc()).all()
    result = []
    for t in txns:
        d = t.to_dict()
        d['enc_payload'] = t.enc_payload
        result.append(d)
    return jsonify({'transactions': result, 'total': len(result)}), 200


@txn_bp.route('/by-account/<int:account_id>', methods=['GET'])
@require_auth
def transactions_by_account(account_id):
    txns = Transaction.query.filter(
        (Transaction.from_account_id == account_id) |
        (Transaction.to_account_id   == account_id)
    ).order_by(Transaction.created_at.desc()).all()
    return jsonify({'transactions': [t.to_dict() for t in txns], 'account_id': account_id}), 200


# ── Lab 5: AES transfer ────────────────────────────────────────────────────────

@txn_bp.route('/transfer', methods=['POST'])
@require_auth
def transfer():
    data = request.get_json() or {}
    enc_payload = data.get('enc_payload')

    if enc_payload:
        try:
            payload = json.loads(_aes_decrypt(enc_payload))
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {e}'}), 400
    else:
        payload = data

    from_acct_num = payload.get('from_account')
    to_acct_num   = payload.get('to_account')
    amount        = float(payload.get('amount', 0))
    description   = payload.get('description', 'Transfer')

    if amount <= 0:
        return jsonify({'error': 'amount must be positive'}), 400

    from_acct = BankAccount.query.filter_by(account_number=from_acct_num).first()
    to_acct   = BankAccount.query.filter_by(account_number=to_acct_num).first()

    if not from_acct or not to_acct:
        return jsonify({'error': 'Account not found'}), 404
    if float(from_acct.balance) < amount:
        return jsonify({'error': 'Insufficient funds'}), 400

    from_acct.balance = float(from_acct.balance) - amount
    to_acct.balance   = float(to_acct.balance) + amount

    txn_count = Transaction.query.count()
    txn_id_str = f"TXN-{str(txn_count+1).zfill(5)}"

    txn_data = {'from': from_acct_num, 'to': to_acct_num,
                'amount': amount, 'desc': description}
    enc = _aes_encrypt(json.dumps(txn_data))

    txn = Transaction(txn_id=txn_id_str, from_account_id=from_acct.id,
                      to_account_id=to_acct.id, amount=amount,
                      description=description, enc_payload=enc)
    db.session.add(txn)
    db.session.commit()

    return jsonify({
        'message': 'Transfer successful',
        'txn_id': txn_id_str,
        'enc_payload': enc,
        'new_balance': float(from_acct.balance),
    }), 200


@txn_bp.route('/decrypt-demo', methods=['POST'])
@require_auth
def decrypt_demo():
    """Lab 5: exposes key/IV used for decryption."""
    data = request.get_json() or {}
    enc  = data.get('enc_payload', '')
    if not enc:
        return jsonify({'error': 'enc_payload required'}), 400
    try:
        plaintext = _aes_decrypt(enc)
        key = current_app.config['AES_KEY']
        iv  = current_app.config['AES_IV']
        return jsonify({
            'plaintext': plaintext,
            'key_used':  key,
            'iv_used':   iv,
            'algorithm': 'AES-256-CBC',
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@txn_bp.route('/encrypt-demo', methods=['POST'])
@require_auth
def encrypt_demo():
    data = request.get_json() or {}
    text = data.get('plaintext', '')
    if not text:
        return jsonify({'error': 'plaintext required'}), 400
    enc = _aes_encrypt(text)
    return jsonify({
        'enc_payload': enc,
        'key': current_app.config['AES_KEY'],
        'iv':  current_app.config['AES_IV'],
    }), 200


# ── Lab 14: XXE (Bulk Transfer Batch Upload) ────────────────────────────────────

@txn_bp.route('/bulk-upload', methods=['POST'])
@require_auth
def bulk_upload():
    """Real banks widely use XML for batch payment files (ISO 20022-style
    NEFT/RTGS batches) — this mirrors that with a simple custom schema:

      <BulkTransferBatch>
        <Transfer>
          <FromAccount>NXB1000000001</FromAccount>
          <ToAccount>NXB1000000003</ToAccount>
          <Amount>500.00</Amount>
          <Description>Vendor payment</Description>
        </Transfer>
      </BulkTransferBatch>

    VULNERABILITY: parsed with lxml.etree.XMLParser(resolve_entities=True,
    no_network=False) — resolve_entities=True is actually lxml's OWN DEFAULT
    (a well-known real-world gotcha), and no_network=False additionally
    allows entities to resolve over HTTP/FTP, not just local files. A
    DOCTYPE-declared external entity gets expanded and reflected straight
    back in the parsed preview below — no blind/out-of-band trickery needed.

    Classic payloads (place `&xxe;` in any <Transfer> field, e.g. Description):
      <!DOCTYPE BulkTransferBatch [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
      <!DOCTYPE BulkTransferBatch [<!ENTITY xxe SYSTEM "file:///app/config.py">]>
      <!DOCTYPE BulkTransferBatch [<!ENTITY xxe SYSTEM "http://redis:6379/">]>
      <!DOCTYPE BulkTransferBatch [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>

    Accepts either raw XML (Content-Type: application/xml) or, like the rest
    of the app, JSON {"enc_payload": "<base64 ciphertext of the raw XML text>"}
    with Content-Type: application/json — same AES key/IV as everywhere else.
    """
    if (request.content_type or '').startswith('application/json'):
        body = request.get_json() or {}
        enc_payload = body.get('enc_payload')
        if not enc_payload:
            return jsonify({'error': 'enc_payload required for JSON uploads'}), 400
        try:
            xml_data = _aes_decrypt(enc_payload).encode('utf-8')
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {e}'}), 400
    else:
        xml_data = request.get_data()

    if not xml_data:
        return jsonify({'error': 'XML body required (Content-Type: application/xml, or application/json with enc_payload)'}), 400

    try:
        parser = etree.XMLParser(resolve_entities=True, no_network=False)
        root = etree.fromstring(xml_data, parser=parser)
    except Exception as e:
        return jsonify({'error': 'XML parse error: %s' % str(e)}), 400

    parsed_transfers = []
    for transfer_el in root.findall('.//Transfer'):
        parsed_transfers.append({
            'from_account': (transfer_el.findtext('FromAccount') or '').strip(),
            'to_account':   (transfer_el.findtext('ToAccount') or '').strip(),
            'amount':       (transfer_el.findtext('Amount') or '').strip(),
            'description':  (transfer_el.findtext('Description') or '').strip(),
        })

    return jsonify({
        'message': 'Batch parsed successfully — review before confirming execution',
        'transfer_count': len(parsed_transfers),
        'parsed_transfers': parsed_transfers,
    }), 200
