# 🏦 MobileBank-ZKP: Zero-Knowledge Banking Application

A full-stack, secure mobile/web banking application built with **Flask**, **PostgreSQL**, and **vanilla JavaScript**, implementing password-less authentication using the **Schnorr Zero-Knowledge Identification Protocol** over a NIST-recommended discrete logarithm group ($L = 3072, N = 256$), as described in the research paper *"MobileBank-ZKP: Mobile Banking Authentication for FinTech Applications Using the Schnorr Zero-Knowledge Identification Protocol"*.

---

## 📋 Table of Contents

- [Overview & Cryptographic Model](#overview--cryptographic-model)
- [Key Security Properties](#key-security-properties)
- [The 3-Move Schnorr Handshake](#the-3-move-schnorr-handshake)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Database Schema](#database-schema)
- [Installation & Setup](#installation--setup)
- [Running the Application](#running-the-application)
- [Testing & Adversarial Evaluation](#testing--adversarial-evaluation)
- [API Reference](#api-reference)

---

## Overview & Cryptographic Model

Conventional retail banking authentication relies on stored secrets (passwords, PINs, salted hashes via bcrypt). If the server database is breached, attacker offline attacks and dictionary attacks endanger the entire customer base.

**MobileBank-ZKP eliminates shared secrets:**
- The customer's private key $x \in [1, q-1]$ is generated locally on their device and **never leaves it**.
- The bank stores only the public key $y = g^x \bmod p$.
- Even if the bank's entire database is leaked, an adversary gains only public keys—from which computing private keys requires solving the intractable Discrete Logarithm Problem (DLP) in a 3072-bit prime field (~128-bit security).
- Authentication runs in **~25 ms**, approximately **10x faster** than bcrypt (cost 12), because a server retaining no verifier pays no deliberate key-stretching overhead.

---

## Key Security Properties

| Property | Password / bcrypt | TOTP | MobileBank-ZKP |
|---|---|---|---|
| Secret never transmitted across wire | ❌ No | ❌ No | ✅ **Yes** |
| Database breach does not expose credentials | ❌ No | ❌ No | ✅ **Yes** |
| Resists offline dictionary / brute force | ❌ No | ✅ Yes | ✅ **Yes** |
| Resists phishing of long-term secret | ❌ No | ❌ No | ✅ **Yes** |
| Resists replay attacks | ❌ No | ✅ Yes | ✅ **Yes** |
| No shared secret stored on server | ✅ Yes | ❌ No | ✅ **Yes** |
| No out-of-band channel required (SMS/email) | ✅ Yes | ❌ No | ✅ **Yes** |
| Resistant to SIM swapping / substitution | ✅ Yes | ❌ No | ✅ **Yes** |

---

## The 3-Move Schnorr Handshake

```
Prover (Customer Device)                     Direction                 Verifier (Bank Server)
─────────────────────────────────────────────────────────────────────────────────────────────
1. Nonce r ← [1, q-1]
   Commitment R = g^r mod p           ───────── R ─────────>   Validates device binding
                                                               Checks lockout & R order
2.                                    <──────── c, sess_id ──  Challenge c ← {0, 1}^256
3. Response s = (r + c·x) mod q       ───────── s ─────────>   Accepts iff g^s ≡ R · y^c (mod p)
                                                               Deletes challenge (single-use)
```

- **Transport Encoding:** All 3072-bit and 256-bit large integers are transmitted as decimal strings over JSON to avoid IEEE-754 precision loss above $2^{53}$.
- **Single-Use Challenges:** Pending challenges are indexed by an unguessable `session_id` (preventing DoS) and consumed immediately upon first verification.
- **Account Lockout:** Sustained brute force triggers account lockout after 5 consecutive failures.
- **Atomic Debits:** All withdrawals and transfers execute via a single conditional predicate update:
  `UPDATE users SET balance = balance - :amount WHERE account_number = :id AND balance >= :amount`
  preventing race-condition concurrent overdrafts and guaranteeing Conservation of Value.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, Flask |
| Database | PostgreSQL 18.x, `psycopg2-binary` |
| Cryptography | Native Python / Web Crypto + JS `BigInt` (NIST SP 800-57, FIPS 186-4) |
| Session & Auth | Bearer Token / `active_sessions` table with immediate revocation |
| Frontend | HTML5, CSS3, Vanilla JavaScript (`schnorr-client.js`) |

---

## Project Structure

```
Banking-System/
├── app.py                      # Flask routes & session security dependencies
├── config/
│   ├── __init__.py
│   └── database.py             # PostgreSQL connection management
├── crypto/
│   ├── __init__.py
│   ├── params.py               # NIST DL group parameters (P: 3072-bit, Q: 256-bit, G)
│   └── schnorr.py              # Shared Schnorr ZKP module (Prover + Verifier)
├── models/
│   ├── __init__.py
│   └── user.py                 # Atomic conditional transfers & fixed-point Decimal ledger
├── services/
│   ├── __init__.py
│   └── authentication.py       # ZKP Registration & 3-Move Handshake logic
├── static/
│   ├── css/style.css
│   ├── js/
│   │   ├── schnorr-client.js   # Client-side BigInt Schnorr keygen & prover math
│   │   └── script.js           # UI integration & 3-move handshake animator
│   └── img/
├── templates/
│   ├── index.html
│   ├── login.html              # ZKP login with live handshake progress
│   ├── register.html           # Device-bound key generation
│   └── dashboard.html          # Protected banking dashboard
├── tests/
│   ├── test_crypto.py          # 19 tests for cryptographic math & subgroup checks
│   ├── test_auth.py            # 5 tests for ZKP registration & public key validation
│   ├── test_handshake.py       # 7 tests for 3-move handshake & replay prevention
│   ├── test_banking.py         # 6 tests for atomic overdrafts & session revocation
│   └── test_adversarial.py     # 14 scripted adversary attacks (Table 3 harness)
├── requirements.txt
├── .env
└── README.md
```

---

## Database Schema (PostgreSQL)

```sql
CREATE DATABASE banking_system;
\c banking_system

-- Users table: stores public key and device binding (NO passwords or hashes)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    account_number INTEGER UNIQUE NOT NULL,
    balance NUMERIC(15, 2) DEFAULT 0.00,
    public_key TEXT,
    device_id VARCHAR(255),
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP
);

-- Pending challenges: single-use, 120s expiry, indexed by unguessable session_id
CREATE TABLE pending_challenges (
    session_id VARCHAR(255) PRIMARY KEY,
    username INTEGER NOT NULL,
    device_id VARCHAR(255) NOT NULL,
    commitment TEXT NOT NULL,
    challenge TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Active sessions: immediate revocation upon logout
CREATE TABLE active_sessions (
    token_id VARCHAR(255) PRIMARY KEY,
    account_number INTEGER NOT NULL,
    token_type VARCHAR(20) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE
);

-- Transactions: audit ledger
CREATE TABLE transactions (
    transaction_id SERIAL PRIMARY KEY,
    from_account INTEGER,
    to_account INTEGER,
    amount NUMERIC(15, 2) NOT NULL,
    transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    transaction_type VARCHAR(50) NOT NULL
);
```

---

## Installation & Setup

### 1. Prerequisites
- Python 3.10+
- PostgreSQL running on `localhost:5432`

### 2. Environment Configuration
Create a `.env` file in the project directory:
```env
DATABASE_URL=localhost
DB_PASSWORD=your_postgres_password
SECRET_KEY=your_random_secret_string
```

### 3. Install Dependencies
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## Running the Application

```powershell
python app.py
```
Open **http://127.0.0.1:5000** in your browser:
1. Navigate to **Register**: enter your name and initial deposit. The browser generates a 3072-bit Schnorr keypair on your device and sends only the public key.
2. Navigate to **Login**: enter your account number. The client detects your stored device private key and executes the live 3-move handshake (`/auth/commit` $\rightarrow$ `/auth/verify`).

---

## Testing & Adversarial Evaluation

The project includes **51 automated tests** covering all cryptographic primitives, transactional invariants, and 14 adversarial attack scripts with 3-valued verdict reporting (`DEFENDED | VULNERABLE | INCONCLUSIVE`).

### Run All Test Suites
```powershell
python tests/test_crypto.py
python tests/test_auth.py
python tests/test_handshake.py
python tests/test_banking.py
python tests/test_adversarial.py
```

### Adversarial Evaluation Results (Table 3)
```
===========================================================================
 MobileBank-ZKP Adversarial Evaluation Harness (Table 3)
 3-Valued Verdict Reporting: [DEFENDED | VULNERABLE | INCONCLUSIVE]
===========================================================================
 [01] Replay of captured transcript       : 🛡️ DEFENDED (Fresh single-use challenge)
 [02] Challenge reuse                     : 🛡️ DEFENDED (Consumed on first use)
 [03] Impersonation without key           : 🛡️ DEFENDED (Soundness error 2^-256)
 [04] Identity-element public key         : 🛡️ DEFENDED (Registration validation)
 [05] Small-subgroup public key           : 🛡️ DEFENDED (Subgroup membership check)
 [06] Unregistered device                 : 🛡️ DEFENDED (Binding checked before challenge)
 [07] Forged token                        : 🛡️ DEFENDED (Signature verification / DB check)
 [08] Algorithm downgrade to none         : 🛡️ DEFENDED (Decoder pinned to valid types)
 [09] Refresh token as access token       : 🛡️ DEFENDED (Token type checked per request)
 [10] Token replayed after logout         : 🛡️ DEFENDED (Session identifier revocation)
 [11] Unauthenticated banking access      : 🛡️ DEFENDED (Dependency on all account routes)
 [12] Concurrent overdraft                : 🛡️ DEFENDED (Atomic conditional update)
 [13] Username enumeration                : 🛡️ DEFENDED (Indistinguishable responses)
 [14] Sustained brute force               : 🛡️ DEFENDED (Lockout after five failures)
===========================================================================
 Evaluation Summary:
   DEFENDED    : 14/14
   VULNERABLE  : 0/14
   INCONCLUSIVE: 0/14
===========================================================================
```

---

## License

Academic Research Implementation — MobileBank-ZKP.
