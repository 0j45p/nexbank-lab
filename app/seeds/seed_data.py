"""
Seed script — run inside the app container:
  docker exec -it nexbank-app python seeds/seed_data.py
"""
import hashlib, json, base64, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

AES_KEY = b'NexBankSecure2024'.ljust(32)[:32]
AES_IV  = b'1234567890123456'


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def aes_enc(d: dict) -> str:
    raw = json.dumps(d).encode()
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return base64.b64encode(cipher.encrypt(pad(raw, AES.block_size))).decode()


def run():
    from app import create_app, db
    from models.user import User
    from models.account import BankAccount, Transaction

    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()

        users_data = [
            dict(user_code='NXB-C-00001', name='Arjun Mehta',   email='arjun@nexbank.local',  mobile='9100000001', password='password123', role='customer', is_verified=True,  kyc_status='Verified',  pan_number='ABCDE1234F', aadhaar_number='123456789012'),
            dict(user_code='NXB-C-00002', name='Priya Nair',    email='priya@nexbank.local',   mobile='9100000002', password='password123', role='customer', is_verified=True,  kyc_status='Verified',  pan_number='FGHIJ5678K', aadhaar_number='234567890123'),
            dict(user_code='NXB-C-00003', name='Rohan Desai',   email='rohan@nexbank.local',   mobile='9100000003', password='password123', role='customer', is_verified=True,  kyc_status='Verified',  pan_number='KLMNO9012P', aadhaar_number='345678901234'),
            dict(user_code='NXB-C-00004', name='Sneha Kapoor',  email='sneha@nexbank.local',   mobile='9100000004', password='password123', role='customer', is_verified=False, kyc_status='Pending',   pan_number='PQRST3456U', aadhaar_number='456789012345'),
            dict(user_code='NXB-A-00001', name='Admin NexBank', email='admin@nexbank.local',   mobile='9999999999', password='Admin@123',   role='admin',    is_verified=True,  kyc_status='Verified',  pan_number='ZZZZZ9999Z', aadhaar_number='999999999999'),
        ]

        users = []
        print("\n=== Seeding Users ===")
        for ud in users_data:
            u = User(user_code=ud['user_code'], name=ud['name'], email=ud['email'],
                     mobile=ud['mobile'], role=ud['role'],
                     is_verified=ud['is_verified'], kyc_status=ud['kyc_status'],
                     pan_number=ud['pan_number'], aadhaar_number=ud['aadhaar_number'])
            u.set_password(ud['password'])
            db.session.add(u)
            users.append(u)
            print(f"  {ud['name']:20s}  mobile={ud['mobile']}  md5={md5(ud['password'])}")
        db.session.commit()

        accounts_data = [
            dict(number='NXB1000000001', user_idx=0, atype='savings',  balance=125000.00),
            dict(number='NXB1000000002', user_idx=0, atype='current',  balance=50000.00),
            dict(number='NXB1000000003', user_idx=1, atype='savings',  balance=75000.00),
            dict(number='NXB1000000004', user_idx=2, atype='savings',  balance=200000.00),
            dict(number='NXB1000000005', user_idx=3, atype='savings',  balance=10000.00),
            dict(number='NXB1000000006', user_idx=4, atype='current',  balance=9999999.00),
        ]

        accounts = []
        print("\n=== Seeding Accounts ===")
        for ad in accounts_data:
            a = BankAccount(account_number=ad['number'], user_id=users[ad['user_idx']].id,
                            account_type=ad['atype'], balance=ad['balance'])
            db.session.add(a)
            accounts.append(a)
            print(f"  {ad['number']}  {ad['atype']:10s}  ₹{ad['balance']:>12,.2f}  owner={users[ad['user_idx']].name}")
        db.session.commit()

        txns_data = [
            dict(txn_id='TXN-00001', fi=0, ti=2, amount=5000.00,   desc='Salary advance'),
            dict(txn_id='TXN-00002', fi=2, ti=3, amount=10000.00,  desc='EMI payment'),
            dict(txn_id='TXN-00003', fi=3, ti=0, amount=2500.00,   desc='Subscription'),
            dict(txn_id='TXN-00004', fi=0, ti=4, amount=1000.00,   desc='Gift transfer'),
            dict(txn_id='TXN-00005', fi=5, ti=0, amount=50000.00,  desc='Admin disbursement'),
            dict(txn_id='TXN-00006', fi=1, ti=2, amount=7500.00,   desc='Vendor payment'),
            dict(txn_id='TXN-00007', fi=4, ti=1, amount=3000.00,   desc='Refund'),
        ]

        print("\n=== Seeding Transactions ===")
        for td in txns_data:
            fa = accounts[td['fi']]
            ta = accounts[td['ti']]
            payload = {'from': fa.account_number, 'to': ta.account_number,
                       'amount': td['amount'], 'desc': td['desc']}
            enc = aes_enc(payload)
            t = Transaction(txn_id=td['txn_id'], from_account_id=fa.id,
                            to_account_id=ta.id, amount=td['amount'],
                            description=td['desc'], enc_payload=enc)
            db.session.add(t)
            print(f"  {td['txn_id']}  ₹{td['amount']:>10,.2f}  {fa.account_number} → {ta.account_number}")
        db.session.commit()

        print("\n=== Seed complete ===")
        print("\nKey credentials for lab exercises:")
        print("  AES key  :", AES_KEY.decode().rstrip('\x00'))
        print("  AES IV   :", AES_IV.decode())
        print("  JWT secret: nexbank2024")
        print("  MD5 salt  : (none)")


if __name__ == '__main__':
    run()
