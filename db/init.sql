-- NexBank Digital — initial schema
-- Created by docker-entrypoint-initdb.d on first run

CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    user_code       VARCHAR(12)  UNIQUE NOT NULL,
    name            VARCHAR(100) NOT NULL,
    email           VARCHAR(120) UNIQUE NOT NULL,
    mobile          VARCHAR(15)  UNIQUE NOT NULL,
    password_hash   VARCHAR(64)  NOT NULL,       -- MD5, no salt
    role            VARCHAR(20)  DEFAULT 'customer',
    is_verified     BOOLEAN      DEFAULT FALSE,
    kyc_status      VARCHAR(20)  DEFAULT 'Pending',
    pan_number      VARCHAR(10),
    aadhaar_number  VARCHAR(12),
    created_at      TIMESTAMP    DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS bank_accounts (
    id              SERIAL PRIMARY KEY,
    account_number  VARCHAR(20)  UNIQUE NOT NULL,
    user_id         INTEGER      REFERENCES users(id) ON DELETE CASCADE,
    account_type    VARCHAR(20)  DEFAULT 'savings',
    balance         NUMERIC(15,2) DEFAULT 0.00,
    ifsc_code       VARCHAR(11)  DEFAULT 'NXBK0000001',
    is_frozen       BOOLEAN      DEFAULT FALSE,
    created_at      TIMESTAMP    DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS transactions (
    id               SERIAL PRIMARY KEY,
    txn_id           VARCHAR(20)  UNIQUE NOT NULL,
    from_account_id  INTEGER      REFERENCES bank_accounts(id),
    to_account_id    INTEGER      REFERENCES bank_accounts(id),
    amount           NUMERIC(15,2) NOT NULL,
    description      VARCHAR(200),
    txn_type         VARCHAR(20)  DEFAULT 'transfer',
    status           VARCHAR(20)  DEFAULT 'completed',
    enc_payload      TEXT,
    created_at       TIMESTAMP    DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS otp_records (
    id          SERIAL PRIMARY KEY,
    mobile      VARCHAR(15)  NOT NULL,
    otp         VARCHAR(6)   NOT NULL,
    purpose     VARCHAR(30)  DEFAULT 'login',
    attempts    INTEGER      DEFAULT 0,
    is_used     BOOLEAN      DEFAULT FALSE,
    created_at  TIMESTAMP    DEFAULT NOW(),
    expires_at  TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reset_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER      REFERENCES users(id) ON DELETE CASCADE,
    token       VARCHAR(64)  NOT NULL,
    is_used     BOOLEAN      DEFAULT FALSE,
    created_at  TIMESTAMP    DEFAULT NOW(),
    expires_at  TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id          SERIAL PRIMARY KEY,
    session_id  VARCHAR(64)  UNIQUE NOT NULL,
    user_id     INTEGER      REFERENCES users(id) ON DELETE CASCADE,
    jwt_token   TEXT,
    ip_address  VARCHAR(45),
    is_active   BOOLEAN      DEFAULT TRUE,
    created_at  TIMESTAMP    DEFAULT NOW(),
    expires_at  TIMESTAMP
);

-- Index on commonly queried columns
CREATE INDEX IF NOT EXISTS idx_otp_mobile     ON otp_records(mobile);
CREATE INDEX IF NOT EXISTS idx_sessions_user  ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_txn_from_acct  ON transactions(from_account_id);
CREATE INDEX IF NOT EXISTS idx_txn_to_acct    ON transactions(to_account_id);
