"""
Bank Account & Transaction models — Lab 7: no ownership validation (IDOR)
"""
from datetime import datetime
from app import db


class BankAccount(db.Model):
    __tablename__ = 'bank_accounts'
    id             = db.Column(db.Integer, primary_key=True)
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    user_id        = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    account_type   = db.Column(db.String(20), default='savings')
    balance        = db.Column(db.Numeric(15, 2), default=0.00)
    ifsc_code      = db.Column(db.String(11), default='NXBK0000001')
    is_frozen      = db.Column(db.Boolean, default=False)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    transactions_sent     = db.relationship('Transaction', foreign_keys='Transaction.from_account_id', backref='from_account', lazy=True)
    transactions_received = db.relationship('Transaction', foreign_keys='Transaction.to_account_id',   backref='to_account',   lazy=True)

    def to_dict(self):
        return {
            'id': self.id, 'account_number': self.account_number,
            'user_id': self.user_id, 'account_type': self.account_type,
            'balance': float(self.balance), 'ifsc_code': self.ifsc_code,
            'is_frozen': self.is_frozen,
        }


class Transaction(db.Model):
    __tablename__ = 'transactions'
    id              = db.Column(db.Integer, primary_key=True)
    txn_id          = db.Column(db.String(20), unique=True, nullable=False)
    from_account_id = db.Column(db.Integer, db.ForeignKey('bank_accounts.id'))
    to_account_id   = db.Column(db.Integer, db.ForeignKey('bank_accounts.id'))
    amount          = db.Column(db.Numeric(15, 2), nullable=False)
    description     = db.Column(db.String(200))
    txn_type        = db.Column(db.String(20), default='transfer')
    status          = db.Column(db.String(20), default='completed')
    enc_payload     = db.Column(db.Text)   # Lab 5: AES-CBC encrypted JSON
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'txn_id': self.txn_id,
            'from_account_id': self.from_account_id, 'to_account_id': self.to_account_id,
            'amount': float(self.amount), 'description': self.description,
            'txn_type': self.txn_type, 'status': self.status,
            'created_at': self.created_at.isoformat(),
        }
