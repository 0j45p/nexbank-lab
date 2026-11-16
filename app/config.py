import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'super_secret_flask_key_123')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://nexbank:nexbank123@localhost:5432/nexbank')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

    # Lab 8: Weak JWT config — alg:none accepted
    JWT_SECRET = os.environ.get('JWT_SECRET', 'nexbank2024')
    JWT_ALGORITHM = os.environ.get('JWT_ALGORITHM', 'HS256')
    JWT_ALLOWED_ALGORITHMS = ['HS256', 'HS384', 'HS512', 'none']

    # Lab 5: AES key baked into config AND into static/js/app.js
    AES_KEY = os.environ.get('AES_KEY', 'NexBankSecure2024')
    AES_IV  = os.environ.get('AES_IV',  '1234567890123456')

    # Lab 2: static salt makes reset tokens predictable
    RESET_TOKEN_SALT = os.environ.get('RESET_TOKEN_SALT', 'nexbank_static_salt')

    OTP_LENGTH = 4
    OTP_EXPIRY_SECONDS = 300
    OTP_RATE_LIMIT = 5   # bypassable via X-Forwarded-For (Lab 1)
