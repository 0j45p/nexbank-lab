"""
Admin Routes — @require_auth but NO role check (broken access control)
Any authenticated user can call these admin endpoints.
"""
import base64, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from flask import Blueprint, request, jsonify, current_app, g
from app import db
from models.user import User, UserSession
from routes.auth import require_auth, _make_jwt

admin_bp = Blueprint('admin', __name__)


def _aes_decrypt(ciphertext_b64: str) -> str:
    """Same AES-256-CBC config as the rest of the app (Lab 5)."""
    key = current_app.config['AES_KEY'].encode().ljust(32)[:32]
    iv  = current_app.config['AES_IV'].encode().ljust(16)[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = base64.b64decode(ciphertext_b64)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()


@admin_bp.route('/users', methods=['GET'])
@require_auth
def list_users():
    users = User.query.all()
    return jsonify({
        'users': [u.to_dict(include_sensitive=True) for u in users],
        'total': len(users),
        'note': 'password_hash is MD5 without salt — crack with hashcat -m 0',
    }), 200


@admin_bp.route('/users/<int:user_id>/role', methods=['PUT'])
@require_auth
def change_role(user_id):
    """Body can be plaintext {"role": "..."} or {"enc_payload": "<base64
    ciphertext of the same JSON>"} — same key/IV as the rest of the app."""
    data = request.get_json() or {}
    enc_payload = data.get('enc_payload')
    if enc_payload:
        try:
            data = json.loads(_aes_decrypt(enc_payload))
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {e}'}), 400
    new_role = data.get('role', 'customer')
    user = User.query.get_or_404(user_id)
    old_role = user.role
    user.role = new_role
    db.session.commit()
    return jsonify({'message': f'Role changed from {old_role} to {new_role}', 'user': user.to_dict()}), 200


@admin_bp.route('/sessions', methods=['GET'])
@require_auth
def list_sessions():
    sessions = UserSession.query.filter_by(is_active=True).all()
    result = []
    for s in sessions:
        user = User.query.get(s.user_id)
        result.append({
            'session_id': s.session_id,
            'user_id':    s.user_id,
            'user_name':  user.name if user else None,
            'jwt_token':  s.jwt_token,
            'ip_address': s.ip_address,
            'expires_at': s.expires_at.isoformat() if s.expires_at else None,
        })
    return jsonify({'sessions': result, 'total': len(result)}), 200


@admin_bp.route('/config', methods=['GET'])
@require_auth
def get_config():
    return jsonify({
        'JWT_SECRET':        current_app.config['JWT_SECRET'],
        'JWT_ALGORITHMS':    current_app.config['JWT_ALLOWED_ALGORITHMS'],
        'AES_KEY':           current_app.config['AES_KEY'],
        'AES_IV':            current_app.config['AES_IV'],
        'RESET_TOKEN_SALT':  current_app.config['RESET_TOKEN_SALT'],
        'DATABASE_URL':      current_app.config['SQLALCHEMY_DATABASE_URI'],
        'REDIS_URL':         current_app.config.get('REDIS_URL', 'redis://redis:6379/0'),
        'DEBUG':             current_app.config.get('DEBUG', False),
    }), 200


@admin_bp.route('/terminate-session/<session_id>', methods=['DELETE'])
@require_auth
def terminate_session(session_id):
    s = UserSession.query.filter_by(session_id=session_id).first_or_404()
    s.is_active = False
    db.session.commit()
    return jsonify({'message': f'Session {session_id} terminated'}), 200


# ── Lab 12: hidden endpoint, only discoverable via the leaked /api/openapi.json ──

@admin_bp.route('/impersonate/<int:user_id>', methods=['POST'])
@require_auth
def impersonate_user(user_id):
    """Not linked from any page in the UI — nothing in the frontend ever calls
    this. It only shows up in the Swagger/OpenAPI spec exposed at
    /api/docs, which was meant for internal tooling only. Same broken-access-
    control pattern as every other /api/admin/* route (no role check), so any
    authenticated customer can mint a valid JWT for ANY user — including the
    admin account — without their password, OTP, or session."""
    target = User.query.get_or_404(user_id)
    token = _make_jwt(target)
    return jsonify({
        'message': f'Impersonation token issued for {target.name} ({target.role})',
        'token': token,
        'user': target.to_dict(),
    }), 200
