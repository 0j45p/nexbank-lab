"""
Auth Routes
Lab 1: OTP Bypass — X-Debug-OTP header, otp_bypass param, X-Forwarded-For rate limit spoof
Lab 2: Predictable Reset Token (MD5 + time window + static salt) + Host Header Injection + logic flaw
Lab 3: Session Fixation — server reuses client-supplied session_id cookie on login
Lab 4: 2FA Step-Skip — auth_step/auth_user_id cookies are client-controlled, no HMAC
Lab 8: JWT alg:none accepted, verify_signature=False, weak secret 'nexbank2024'
"""
import base64, hashlib, json, random, secrets, time
from datetime import datetime, timedelta
from functools import wraps

import jwt
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from flask import Blueprint, request, jsonify, current_app, g, make_response

from app import db
from models.user import User, OTPRecord, ResetToken, UserSession

auth_bp = Blueprint('auth', __name__)


def _aes_decrypt(ciphertext_b64):
    """AES-256-CBC decrypt. Key and IV are hardcoded in frontend app.js."""
    key = current_app.config['AES_KEY'].encode().ljust(32)[:32]
    iv  = current_app.config['AES_IV'].encode().ljust(16)[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = base64.b64decode(ciphertext_b64)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()


def _client_ip():
    # Lab 1: uses attacker-controlled header for rate limiting
    return (request.headers.get('X-Forwarded-For') or
            request.headers.get('X-Real-IP') or
            request.remote_addr or '127.0.0.1')


def _make_jwt(user):
    payload = {
        'user_id': user.id, 'user_code': user.user_code,
        'role': user.role, 'name': user.name, 'email': user.email,
        'iat': int(datetime.utcnow().timestamp()),
        'exp': int((datetime.utcnow() + timedelta(hours=24)).timestamp()),
    }
    return jwt.encode(payload, current_app.config['JWT_SECRET'], algorithm='HS256')


def _decode_jwt(token):
    # Lab 8: verify_signature=False — any token accepted including alg:none
    try:
        return jwt.decode(token, current_app.config['JWT_SECRET'],
                          algorithms=current_app.config['JWT_ALLOWED_ALGORITHMS'],
                          options={"verify_signature": False})
    except Exception:
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception:
            return None


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        hdr = request.headers.get('Authorization', '')
        if hdr.startswith('Bearer '):
            token = hdr[7:]
        if not token:
            token = request.cookies.get('auth_token')
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        payload = _decode_jwt(token)
        if not payload:
            return jsonify({'error': 'Invalid token'}), 401
        user = User.query.get(payload.get('user_id'))
        if not user:
            return jsonify({'error': 'User not found'}), 401
        g.current_user = user
        g.token_payload = payload
        return f(*args, **kwargs)
    return decorated


# ── Lab 1: OTP ────────────────────────────────────────────────────────────────

@auth_bp.route('/send-otp', methods=['POST'])
def send_otp():
    data   = request.get_json() or {}
    mobile = data.get('mobile', '').strip()
    if not mobile:
        return jsonify({'error': 'mobile required'}), 400

    user = User.query.filter_by(mobile=mobile).first()
    if not user:
        return jsonify({'error': f'No account registered with mobile {mobile}'}), 404

    # Rate limit keyed on attacker-controlled IP header
    ip  = _client_ip()
    key = f'otp_rate:{ip}'
    cnt = current_app.redis.incr(key)
    if cnt == 1:
        current_app.redis.expire(key, 60)
    if cnt > current_app.config['OTP_RATE_LIMIT']:
        return jsonify({'error': 'Rate limit exceeded. Try again in 60s.'}), 429

    otp = ''.join([str(random.randint(0, 9)) for _ in range(current_app.config['OTP_LENGTH'])])
    record = OTPRecord(mobile=mobile, otp=otp, purpose='login',
                       expires_at=datetime.utcnow() + timedelta(seconds=current_app.config['OTP_EXPIRY_SECONDS']))
    db.session.add(record)
    db.session.commit()

    resp = make_response(jsonify({'message': f'OTP sent to {mobile}', 'otp_id': record.id,
                                  'expires_in': current_app.config['OTP_EXPIRY_SECONDS']}))
    # Lab 1: OTP leaked in response header
    resp.headers['X-Debug-OTP']     = otp
    resp.headers['X-OTP-Expiry']    = str(record.expires_at)
    resp.headers['X-Rate-Limit-IP'] = ip
    return resp, 200


@auth_bp.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json() or {}

    # Client-side AES-CBC encryption: frontend encrypts {mobile,otp} before sending.
    # Key is hardcoded in app.js — decryption is trivial for anyone who reads the source.
    enc_payload = data.get('enc_payload')
    if enc_payload:
        try:
            inner = json.loads(_aes_decrypt(enc_payload))
            data  = inner   # replace data with decrypted content
        except Exception as e:
            return jsonify({'error': f'Decryption failed: {e}', 'hint': 'Key is in /static/js/app.js'}), 400

    mobile     = data.get('mobile', '').strip()
    otp        = data.get('otp', '')
    otp_bypass = data.get('otp_bypass', False)

    if not mobile:
        return jsonify({'error': 'mobile required'}), 400

    # Lab 1: bypass parameter
    if otp_bypass in (True, 'true', '1', 1):
        user = User.query.filter_by(mobile=mobile).first()
        if user:
            return jsonify({'verified': True, 'user_id': user.id, 'message': 'Bypassed'}), 200

    if not otp:
        return jsonify({'error': 'otp required'}), 400

    record = OTPRecord.query.filter_by(mobile=mobile, is_used=False)\
                            .order_by(OTPRecord.created_at.desc()).first()
    if not record:
        return jsonify({'error': 'No active OTP. Request a new one.'}), 400

    record.attempts += 1
    db.session.commit()

    if record.otp != str(otp):
        return jsonify({'error': 'Invalid OTP', 'attempts': record.attempts,
                        'hint': f'OTP is {len(record.otp)} digits'}), 400

    record.is_used = True
    db.session.commit()
    user = User.query.filter_by(mobile=mobile).first()
    return jsonify({'verified': True, 'user_id': user.id if user else None}), 200


@auth_bp.route('/login', methods=['POST'])
def login():
    """Lab 3 (session fixation) + Lab 4 (2FA step-skip via forged cookies)."""
    data = request.get_json() or {}
    mobile       = data.get('mobile', '').strip()
    password     = data.get('password', '')
    otp_verified = data.get('otp_verified', False)
    user_id      = data.get('user_id')

    # Lab 4: auth_step=2 cookie with any user_id completes login
    step         = request.cookies.get('auth_step', '0')
    step_user_id = request.cookies.get('auth_user_id', '')

    if step == '2' and step_user_id:
        user = User.query.get(int(step_user_id))
        if user:
            token = _make_jwt(user)
            sid   = request.cookies.get('session_id') or secrets.token_hex(16)  # Lab 3: reuse
            resp  = make_response(jsonify({'message': '2FA complete', 'token': token, 'user': user.to_dict()}))
            resp.set_cookie('auth_token',   token, httponly=False, secure=False, samesite='Lax')
            resp.set_cookie('session_id',   sid,   httponly=False)
            resp.set_cookie('auth_step',    '', expires=0)
            resp.set_cookie('auth_user_id', '', expires=0)
            _save_session(user, token, sid)
            return resp, 200

    if mobile and password:
        user = User.query.filter_by(mobile=mobile).first()
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid credentials'}), 401
        resp = make_response(jsonify({'message': 'Password OK. OTP required.',
                                      'step': 2, 'user_id': user.id}))
        resp.set_cookie('auth_step',    '2',           httponly=False)
        resp.set_cookie('auth_user_id', str(user.id),  httponly=False)
        return resp, 200

    if otp_verified and user_id:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        token = _make_jwt(user)
        sid   = request.cookies.get('session_id') or secrets.token_hex(16)  # Lab 3
        resp  = make_response(jsonify({'message': 'Login successful', 'token': token, 'user': user.to_dict()}))
        resp.set_cookie('auth_token', token, httponly=False, secure=False)
        resp.set_cookie('session_id', sid,   httponly=False)
        _save_session(user, token, sid)
        return resp, 200

    return jsonify({'error': 'Provide mobile+password or otp_verified+user_id'}), 400


def _save_session(user, token, sid):
    existing = UserSession.query.filter_by(session_id=sid).first()
    if existing:
        existing.jwt_token = token
        existing.is_active = True
    else:
        db.session.add(UserSession(session_id=sid, user_id=user.id, jwt_token=token,
                                   ip_address=_client_ip(),
                                   expires_at=datetime.utcnow() + timedelta(hours=24)))
    db.session.commit()


# ── Lab 2: Password Reset ──────────────────────────────────────────────────────

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    data  = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    if not email:
        return jsonify({'error': 'email required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': f'No account found for {email}'}), 404

    # Lab 2: token = MD5(email + time_window + salt) — predictable
    window    = str(int(time.time() // 60))
    token_raw = f"{email}{window}{current_app.config['RESET_TOKEN_SALT']}"
    token     = hashlib.md5(token_raw.encode()).hexdigest()

    db.session.add(ResetToken(user_id=user.id, token=token,
                              expires_at=datetime.utcnow() + timedelta(minutes=15)))
    db.session.commit()

    # Lab 2: Host Header Injection
    host = (request.headers.get('X-Forwarded-Host') or
            request.headers.get('Host') or 'nexbank.local')
    reset_link = f"http://{host}/reset-password?token={token}"

    return jsonify({
        'message': 'Reset link generated',
        'reset_link': reset_link,
        'token': token,
        'debug_host': host,
        'debug_time_window': window,
    }), 200


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    data     = request.get_json() or {}
    token    = data.get('token', '').strip()
    user_id  = data.get('user_id')   # Lab 2: logic flaw — no token needed
    new_pass = data.get('new_password', '')

    if not new_pass:
        return jsonify({'error': 'new_password required'}), 400

    if token:
        rt = ResetToken.query.filter_by(token=token, is_used=False).first()
        if not rt or datetime.utcnow() > rt.expires_at:
            return jsonify({'error': 'Invalid or expired token'}), 400
        user = User.query.get(rt.user_id)
        rt.is_used = True
    elif user_id:
        user = User.query.get(int(user_id))
        if not user:
            return jsonify({'error': 'User not found'}), 404
    else:
        return jsonify({'error': 'token or user_id required'}), 400

    user.set_password(new_pass)
    db.session.commit()
    return jsonify({'message': f'Password reset for {user.email}'}), 200


# ── Lab 8: JWT endpoints ───────────────────────────────────────────────────────

@auth_bp.route('/token-info', methods=['GET'])
@require_auth
def token_info():
    return jsonify({'payload': g.token_payload}), 200


@auth_bp.route('/forge-token', methods=['POST'])
def forge_token():
    """Lab 8 demo: sign any payload with the weak secret."""
    data    = request.get_json() or {}
    payload = data.get('payload', {})
    alg     = data.get('algorithm', 'HS256')
    if alg == 'none':
        import base64, json
        hdr = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=')
        pay = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
        token = f"{hdr.decode()}.{pay.decode()}."
    else:
        token = jwt.encode(payload, current_app.config['JWT_SECRET'], algorithm=alg)
    return jsonify({'token': token, 'secret_used': current_app.config['JWT_SECRET']}), 200


@auth_bp.route('/logout', methods=['POST'])
@require_auth
def logout():
    UserSession.query.filter_by(user_id=g.current_user.id, is_active=True).update({'is_active': False})
    db.session.commit()
    resp = make_response(jsonify({'message': 'Logged out'}))
    resp.delete_cookie('auth_token')
    resp.delete_cookie('session_id')
    return resp, 200


@auth_bp.route('/me', methods=['GET'])
@require_auth
def me():
    return jsonify({'user': g.current_user.to_dict(include_sensitive=True)}), 200
