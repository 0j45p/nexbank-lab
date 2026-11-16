"""
Debug Routes — NO authentication on any endpoint.
Intentional backdoor for the training lab.
"""
import os
from flask import Blueprint, request, jsonify, current_app
from app import db
from models.user import User, UserSession

debug_bp = Blueprint('debug', __name__)


@debug_bp.route('/env', methods=['GET'])
def debug_env():
    return jsonify({'env': dict(os.environ)}), 200


@debug_bp.route('/users', methods=['GET'])
def debug_users():
    users = User.query.all()
    return jsonify({
        'users': [u.to_dict(include_sensitive=True) for u in users],
        'count': len(users),
        'note': 'password_hash = MD5(password) — no salt',
    }), 200


@debug_bp.route('/sessions', methods=['GET'])
def debug_sessions():
    sessions = UserSession.query.filter_by(is_active=True).all()
    result = []
    for s in sessions:
        user = User.query.get(s.user_id)
        result.append({
            'session_id': s.session_id,
            'user_id':    s.user_id,
            'user_name':  user.name if user else 'unknown',
            'jwt_token':  s.jwt_token,
            'ip_address': s.ip_address,
        })
    return jsonify({'active_sessions': result}), 200


@debug_bp.route('/config', methods=['GET'])
def debug_config():
    return jsonify({
        'JWT_SECRET':       current_app.config['JWT_SECRET'],
        'AES_KEY':          current_app.config['AES_KEY'],
        'AES_IV':           current_app.config['AES_IV'],
        'RESET_TOKEN_SALT': current_app.config['RESET_TOKEN_SALT'],
        'DB_URL':           current_app.config['SQLALCHEMY_DATABASE_URI'],
        'REDIS_URL':        current_app.config.get('REDIS_URL', 'redis://redis:6379/0'),
    }), 200


@debug_bp.route('/sql', methods=['POST'])
def debug_sql():
    """Direct SQL execution — Lab extra: SQLi demo surface."""
    data  = request.get_json() or {}
    query = data.get('query', '')
    if not query:
        return jsonify({'error': 'query required'}), 400
    try:
        result = db.session.execute(db.text(query))
        rows = [dict(row._mapping) for row in result]
        return jsonify({'rows': rows, 'count': len(rows)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@debug_bp.route('/ping', methods=['GET'])
def ping():
    return jsonify({'status': 'ok', 'app': 'NexBank Digital', 'debug': True}), 200
