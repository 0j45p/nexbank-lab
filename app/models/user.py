"""
User model — Lab 6: passwords stored as MD5 (no salt), intentional crypto failure
"""
import hashlib
from datetime import datetime
from app import db


class User(db.Model):
    __tablename__ = 'users'
    id             = db.Column(db.Integer, primary_key=True)
    user_code      = db.Column(db.String(12), unique=True, nullable=False)
    name           = db.Column(db.String(100), nullable=False)
    email          = db.Column(db.String(120), unique=True, nullable=False)
    mobile         = db.Column(db.String(15), unique=True, nullable=False)
    password_hash  = db.Column(db.String(64), nullable=False)   # MD5, no salt
    role           = db.Column(db.String(20), default='customer')
    is_verified    = db.Column(db.Boolean, default=False)
    kyc_status     = db.Column(db.String(20), default='Pending')
    pan_number     = db.Column(db.String(10))
    aadhaar_number = db.Column(db.String(12))
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    accounts     = db.relationship('BankAccount', backref='user', lazy=True)
    sessions     = db.relationship('UserSession', backref='user', lazy=True)
    reset_tokens = db.relationship('ResetToken', backref='user', lazy=True)

    def set_password(self, password):
        # Lab 6: MD5, no salt — intentional
        self.password_hash = hashlib.md5(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password_hash == hashlib.md5(password.encode()).hexdigest()

    def to_dict(self, include_sensitive=False):
        d = {
            'id': self.id, 'user_code': self.user_code, 'name': self.name,
            'email': self.email, 'mobile': self.mobile, 'role': self.role,
            'is_verified': self.is_verified, 'kyc_status': self.kyc_status,
        }
        if include_sensitive:
            d.update({
                'pan_number': self.pan_number,
                'aadhaar_number': self.aadhaar_number,
                'password_hash': self.password_hash,   # intentionally exposed
            })
        return d


class OTPRecord(db.Model):
    __tablename__ = 'otp_records'
    id         = db.Column(db.Integer, primary_key=True)
    mobile     = db.Column(db.String(15), nullable=False)
    otp        = db.Column(db.String(6), nullable=False)
    purpose    = db.Column(db.String(30), default='login')
    attempts   = db.Column(db.Integer, default=0)
    is_used    = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)


class ResetToken(db.Model):
    __tablename__ = 'reset_tokens'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token      = db.Column(db.String(64), nullable=False)
    is_used    = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)


class UserSession(db.Model):
    __tablename__ = 'user_sessions'
    id         = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), unique=True, nullable=False)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    jwt_token  = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    is_active  = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
