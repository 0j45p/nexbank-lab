"""
NexBank Digital — Deliberately Vulnerable Banking Lab
RedCIPHER Security Training | For authorized use only
"""
import redis as redis_lib
from flask import Flask, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from config import Config

db = SQLAlchemy()

# Lab 12: internal-only API documentation, never meant to be public.
# Deliberately includes the hidden impersonation endpoint (routes/admin.py)
# that isn't referenced anywhere in the actual frontend.
#
# Has a real bearerAuth security scheme + request-body schemas so Swagger
# UI's "Try it out" is actually usable end-to-end: click the padlock (top
# right of /api/docs) once, paste "Bearer <your JWT>", and every endpoint's
# "Try it out" button sends it automatically from then on — no separate
# curl/DevTools step needed to actually fire the requests from the docs page.
def _json_body(example: dict, required=True):
    return {
        "required": required,
        "content": {"application/json": {"schema": {
            "type": "object",
            "properties": {k: {"type": "string", "example": v} for k, v in example.items()},
        }}},
    }


def _path_param(name, type_="integer"):
    return {"name": name, "in": "path", "required": True, "schema": {"type": type_}}


OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "NexBank Internal API", "version": "1.0.0",
             "description": "INTERNAL USE ONLY — do not share outside the platform team."},
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
        }
    },
    "security": [{"bearerAuth": []}],
    "paths": {
        "/api/auth/send-otp": {"post": {"summary": "Send login OTP", "security": [],
                                         "requestBody": _json_body({"mobile": "9100000001"})}},
        "/api/auth/verify-otp": {"post": {"summary": "Verify OTP / login step 1", "security": [],
                                           "requestBody": _json_body({"mobile": "9100000001", "otp": "1234", "otp_bypass": "true"})}},
        "/api/auth/login": {"post": {"summary": "Password + 2FA login", "security": [],
                                      "requestBody": _json_body({"mobile": "9100000001", "password": "password123"})}},
        "/api/auth/forgot-password": {"post": {"summary": "Request password reset", "security": [],
                                                "requestBody": _json_body({"email": "arjun@nexbank.local"})}},
        "/api/auth/reset-password": {"post": {"summary": "Reset password with token", "security": [],
                                               "requestBody": _json_body({"user_id": "2", "new_password": "hacked123"})}},
        "/api/account/{account_id}": {"get": {"summary": "Get account details",
                                               "parameters": [_path_param("account_id")]}},
        "/api/account/user/{user_id}/profile": {"get": {"summary": "Get user profile",
                                                          "parameters": [_path_param("user_id")]}},
        "/api/account/statement/download": {"get": {"summary": "Download account statement",
                                                      "parameters": [{"name": "file", "in": "query", "schema": {"type": "string", "example": "../config.py"}}]}},
        "/api/account/receipt/download": {"get": {"summary": "Download a transaction receipt PDF with a custom letterhead logo URL",
                                                   "parameters": [
                                                       {"name": "logo_url", "in": "query", "schema": {"type": "string", "example": "file:///app/config.py"}},
                                                       {"name": "txn_id", "in": "query", "schema": {"type": "string", "example": "TXN-00001"}},
                                                   ]}},
        "/api/txn/{txn_id}": {"get": {"summary": "Get transaction by ID", "parameters": [_path_param("txn_id", "string")]}},
        "/api/txn/transfer": {"post": {"summary": "Transfer funds between accounts",
                                        "requestBody": _json_body({"from_account": "NXB1000000001", "to_account": "NXB1000000003",
                                                                    "amount": "1", "description": "test"})}},
        "/api/txn/bulk-upload": {"post": {"summary": "Upload an XML batch of NEFT/RTGS transfers for parsing",
                                           "requestBody": {"required": True, "content": {"application/xml": {"schema": {"type": "string"},
                                               "example": "<BulkTransferBatch><Transfer><FromAccount>NXB1000000001</FromAccount>"
                                                          "<ToAccount>NXB1000000003</ToAccount><Amount>1</Amount>"
                                                          "<Description>test</Description></Transfer></BulkTransferBatch>"}}}}},
        "/api/admin/users": {"get": {"summary": "List all users (internal/admin)"}},
        "/api/admin/users/{user_id}/role": {"put": {"summary": "Change a user's role (internal/admin)",
                                                      "parameters": [_path_param("user_id")],
                                                      "requestBody": _json_body({"role": "admin"})}},
        "/api/admin/config": {"get": {"summary": "Read runtime config (internal/admin)"}},
        "/api/account/request-role-upgrade": {"post": {"summary": "Self-service account tier upgrade request",
                                                         "requestBody": _json_body({"requested_role": "admin"})}},
        "/api/admin/impersonate/{user_id}": {
            "post": {
                "summary": "[INTERNAL-ONLY] Issue a session token for any user",
                "description": "Used by platform support tooling for account-recovery impersonation. "
                                "Must never be reachable from the customer-facing app — internal callers only.",
                "parameters": [_path_param("user_id")],
            }
        },
    },
}


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    app.redis = redis_lib.from_url(app.config['REDIS_URL'], decode_responses=True)

    from routes.auth    import auth_bp
    from routes.txn     import txn_bp
    from routes.account import account_bp
    from routes.admin   import admin_bp
    from routes.debug   import debug_bp

    app.register_blueprint(auth_bp,    url_prefix='/api/auth')
    app.register_blueprint(txn_bp,     url_prefix='/api/txn')
    app.register_blueprint(account_bp, url_prefix='/api/account')
    app.register_blueprint(admin_bp,   url_prefix='/api/admin')
    app.register_blueprint(debug_bp,   url_prefix='/debug')

    @app.route('/')
    def index(): return render_template('index.html')

    @app.route('/login')
    def login_page(): return render_template('login.html')

    @app.route('/dashboard')
    def dashboard_page(): return render_template('dashboard.html')

    @app.route('/transactions')
    def transactions_page(): return render_template('transactions.html')

    @app.route('/transfer')
    def transfer_page(): return render_template('transfer.html')

    @app.route('/profile')
    def profile_page(): return render_template('profile.html')

    @app.route('/forgot-password')
    def forgot_page(): return render_template('forgot.html')

    @app.route('/lab1')
    def lab1_page(): return render_template('lab1.html')

    @app.route('/lab2')
    def lab2_page(): return render_template('lab2.html')

    @app.route('/lab3')
    def lab3_page(): return render_template('lab3.html')

    @app.route('/lab/ato')
    def ato_page(): return render_template('takeover.html')

    # Lab 12: internal API docs left publicly reachable — no auth on either
    # route. The spec below documents /api/admin/impersonate/{user_id}, which
    # is otherwise unlinked anywhere in the UI (see routes/admin.py).
    @app.route('/api/docs')
    def api_docs_page(): return render_template('swagger.html')

    @app.route('/api/openapi.json')
    def openapi_spec(): return jsonify(OPENAPI_SPEC)

    # Verbose 500 handler — intentional info disclosure
    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({
            'error': str(e),
            'type': type(e).__name__,
            'config': {
                'database': app.config['SQLALCHEMY_DATABASE_URI'],
                'jwt_secret': app.config['JWT_SECRET'],
                'aes_key': app.config['AES_KEY'],
            }
        }), 500

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'Not found', 'path': str(e)}), 404

    with app.app_context():
        db.create_all()

    return app

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
