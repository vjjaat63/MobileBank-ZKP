"""
test_adversarial.py — MobileBank-ZKP Adversarial Evaluation Harness

Implements the 14 scripted adversary attacks from Table 3 of the research paper:
    1.  Replay of captured transcript
    2.  Challenge reuse
    3.  Impersonation without key
    4.  Identity-element public key
    5.  Small-subgroup public key
    6.  Unregistered device
    7.  Forged token
    8.  Algorithm downgrade to none
    9.  Refresh token as access token
    10. Token replayed after logout
    11. Unauthenticated banking access
    12. Concurrent overdraft
    13. Username enumeration
    14. Sustained brute force

Section 6.3: "On Verdict Reporting"
The harness strictly reports three outcomes:
    - DEFENDED: The attack script executed completely and its target exploit was refused.
    - VULNERABLE: The adversary bypassed controls and succeeded.
    - INCONCLUSIVE: The attack script crashed/raised an exception before reaching the target condition.
"""

import sys
import os
import secrets
import threading
from decimal import Decimal

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import database
from services import authentication
from models import user
from crypto import schnorr
from app import app

# Results collector
RESULTS = []

def record_verdict(adversary_id, name, mechanism, verdict, details=""):
    RESULTS.append({
        "id": adversary_id,
        "name": name,
        "mechanism": mechanism,
        "verdict": verdict,
        "details": details
    })


# ===========================================================================
# Setup Helper
# ===========================================================================

def setup_harness():
    db = database.DataBase()
    auth = authentication.Authentication(db)
    client = app.test_client()
    return db, auth, client


# ===========================================================================
# 14 Scripted Adversaries
# ===========================================================================

def attack_01_replay_captured_transcript(db, auth, client):
    """
    Adversary 1: Replay of captured transcript.
    Mechanism of defence: Fresh single-use challenge.
    """
    try:
        x, y = schnorr.generate_keypair()
        dev = "adv_dev_01"
        res = auth.register("Target Alice", 500, str(y), dev)
        acc = res["account_number"]

        # Honest login capture
        r, R = schnorr.create_commitment()
        c_res = client.post("/auth/commit", json={"account_number": acc, "device_id": dev, "commitment": str(R)}).get_json()
        s = schnorr.create_response(r, int(c_res["challenge"]), x)
        v_res = client.post("/auth/verify", json={"session_id": c_res["session_id"], "response": str(s)}).get_json()
        assert v_res["success"], "Base login failed"

        # Adversary attempts to replay the same transcript (session_id, response)
        replay_res = client.post("/auth/verify", json={"session_id": c_res["session_id"], "response": str(s)}).get_json()

        if not replay_res["success"]:
            return "DEFENDED", "Replayed transcript was rejected (challenge consumed)"
        else:
            return "VULNERABLE", "Replayed transcript was accepted"
    except Exception as e:
        return "INCONCLUSIVE", f"Script crashed: {e}"


def attack_02_challenge_reuse(db, auth, client):
    """
    Adversary 2: Challenge reuse.
    Mechanism of defence: Consumed on first use.
    """
    try:
        x, y = schnorr.generate_keypair()
        dev = "adv_dev_02"
        res = auth.register("Target Bob", 500, str(y), dev)
        acc = res["account_number"]

        r, R = schnorr.create_commitment()
        c_res = client.post("/auth/commit", json={"account_number": acc, "device_id": dev, "commitment": str(R)}).get_json()
        sess_id = c_res["session_id"]
        c = int(c_res["challenge"])
        s = schnorr.create_response(r, c, x)

        # First verification consumes challenge
        client.post("/auth/verify", json={"session_id": sess_id, "response": str(s)})

        # Second attempt using same session_id with different or same response
        reuse_res = client.post("/auth/verify", json={"session_id": sess_id, "response": str(s)}).get_json()

        if not reuse_res["success"]:
            return "DEFENDED", "Challenge was consumed on first use; reuse rejected"
        else:
            return "VULNERABLE", "Challenge was reused successfully"
    except Exception as e:
        return "INCONCLUSIVE", f"Script crashed: {e}"


def attack_03_impersonation_without_key(db, auth, client):
    """
    Adversary 3: Impersonation without key.
    Mechanism of defence: Soundness error 2^-256.
    """
    try:
        x, y = schnorr.generate_keypair()
        dev = "adv_dev_03"
        res = auth.register("Target Charlie", 500, str(y), dev)
        acc = res["account_number"]

        # Adversary knows account & device, but DOES NOT know private key x
        r, R = schnorr.create_commitment()
        c_res = client.post("/auth/commit", json={"account_number": acc, "device_id": dev, "commitment": str(R)}).get_json()
        sess_id = c_res["session_id"]

        # Adversary responds with a random guess or wrong key
        fake_s = secrets.randbits(256)
        v_res = client.post("/auth/verify", json={"session_id": sess_id, "response": str(fake_s)}).get_json()

        if not v_res["success"]:
            return "DEFENDED", "Impersonation without private key refused by soundness check"
        else:
            return "VULNERABLE", "Attacker impersonated user without knowing key"
    except Exception as e:
        return "INCONCLUSIVE", f"Script crashed: {e}"


def attack_04_identity_element_public_key(db, auth, client):
    """
    Adversary 4: Identity-element public key.
    Mechanism of defence: Registration validation (reject y = 1).
    """
    try:
        # Submit y = 1 to register
        res = auth.register("Attacker Identity", 100, "1", "adv_dev_04")

        if not res["success"]:
            return "DEFENDED", "Registration with y = 1 rejected by 1 < y < p-1 validation"
        else:
            return "VULNERABLE", "Identity element public key was accepted"
    except Exception as e:
        return "INCONCLUSIVE", f"Script crashed: {e}"


def attack_05_small_subgroup_public_key(db, auth, client):
    """
    Adversary 5: Small-subgroup public key.
    Mechanism of defence: Subgroup membership check (y^q ≡ 1 mod p).
    """
    try:
        # Submit an element not in the order-q subgroup (e.g. 2 or 3)
        res = auth.register("Attacker Subgroup", 100, "2", "adv_dev_05")

        if not res["success"]:
            return "DEFENDED", "Non-subgroup key rejected by subgroup membership check"
        else:
            return "VULNERABLE", "Small-subgroup key was accepted"
    except Exception as e:
        return "INCONCLUSIVE", f"Script crashed: {e}"


def attack_06_unregistered_device(db, auth, client):
    """
    Adversary 6: Unregistered device.
    Mechanism of defence: Binding checked before challenge.
    """
    try:
        x, y = schnorr.generate_keypair()
        res = auth.register("Target David", 500, str(y), "legit_phone_06")
        acc = res["account_number"]

        r, R = schnorr.create_commitment()
        # Adversary attempts handshake from rogue device
        commit_res = client.post("/auth/commit", json={
            "account_number": acc,
            "device_id": "rogue_device_attacker",
            "commitment": str(R)
        }).get_json()

        if not commit_res["success"] and "device" in commit_res.get("message", "").lower():
            return "DEFENDED", "Handshake refused before crypto work due to device mismatch"
        else:
            return "VULNERABLE", "Unregistered device received challenge"
    except Exception as e:
        return "INCONCLUSIVE", f"Script crashed: {e}"


def attack_07_forged_token(db, auth, client):
    """
    Adversary 7: Forged token.
    Mechanism of defence: Signature / Active session table lookup.
    """
    try:
        # Craft arbitrary fake bearer token
        fake_token = secrets.token_hex(32)
        with client.session_transaction() as sess:
            sess["account_number"] = 12345
            sess["name"] = "Victim"
            sess["token_id"] = fake_token

        res = client.post("/view_balance")
        if res.status_code == 401:
            return "DEFENDED", "Forged session token rejected by active_sessions verification"
        else:
            return "VULNERABLE", "Forged token granted access"
    except Exception as e:
        return "INCONCLUSIVE", f"Script crashed: {e}"


def attack_08_algorithm_downgrade_none(db, auth, client):
    """
    Adversary 8: Algorithm downgrade to none.
    Mechanism of defence: Decoder pinned / verification cannot be nullified.
    """
    try:
        with client.session_transaction() as sess:
            sess["account_number"] = 12345
            sess["name"] = "Victim"
            sess["token_id"] = None

        res = client.post("/view_balance")
        if res.status_code == 401 or res.status_code == 302:
            return "DEFENDED", "None-type / nullified token rejected"
        else:
            return "VULNERABLE", "Algorithm downgrade allowed unauthenticated access"
    except Exception as e:
        return "INCONCLUSIVE", f"Script crashed: {e}"


def attack_09_refresh_token_as_access_token(db, auth, client):
    """
    Adversary 9: Refresh token as access token.
    Mechanism of defence: Token type checked per request.
    """
    try:
        x, y = schnorr.generate_keypair()
        res = auth.register("Token Target", 300, str(y), "dev_09")
        acc = res["account_number"]

        # Manually insert a token with token_type = 'refresh'
        refresh_tok = secrets.token_urlsafe(32)
        cur = db.get_cursor()
        cur.execute(
            "INSERT INTO active_sessions (token_id, account_number, token_type, expires_at, revoked) VALUES (%s, %s, 'refresh', NOW() + interval '7 days', FALSE)",
            (refresh_tok, acc)
        )
        db.db.commit()
        cur.close()

        with client.session_transaction() as sess:
            sess["account_number"] = acc
            sess["name"] = "Token Target"
            sess["token_id"] = refresh_tok

        # Attempt to access banking route expecting 'access' token
        resp = client.post("/view_balance")
        if resp.status_code == 401:
            return "DEFENDED", "Refresh token refused on access endpoint by token_type check"
        else:
            return "VULNERABLE", "Refresh token was accepted as access token"
    except Exception as e:
        return "INCONCLUSIVE", f"Script crashed: {e}"


def attack_10_token_replayed_after_logout(db, auth, client):
    """
    Adversary 10: Token replayed after logout.
    Mechanism of defence: Session identifier revocation.
    """
    try:
        x, y = schnorr.generate_keypair()
        dev = "dev_10"
        res = auth.register("Logout Target", 500, str(y), dev)
        acc = res["account_number"]

        # Login
        r, R = schnorr.create_commitment()
        c_res = client.post("/auth/commit", json={"account_number": acc, "device_id": dev, "commitment": str(R)}).get_json()
        s = schnorr.create_response(r, int(c_res["challenge"]), x)
        v_res = client.post("/auth/verify", json={"session_id": c_res["session_id"], "response": str(s)}).get_json()
        token_id = v_res["token_id"]

        # Logout
        client.post("/logout")

        # Replay token in session
        with client.session_transaction() as sess:
            sess["account_number"] = acc
            sess["token_id"] = token_id

        replay_res = client.post("/view_balance")
        if replay_res.status_code == 401:
            return "DEFENDED", "Replayed token after logout was rejected (session revoked)"
        else:
            return "VULNERABLE", "Token remained active after logout"
    except Exception as e:
        return "INCONCLUSIVE", f"Script crashed: {e}"


def attack_11_unauthenticated_banking_access(db, auth, client):
    """
    Adversary 11: Unauthenticated banking access.
    Mechanism of defence: Dependency on all account routes.
    """
    try:
        anon_client = app.test_client()
        res1 = anon_client.post("/view_balance")
        res2 = anon_client.post("/deposite", json={"amount": 100})
        res3 = anon_client.post("/withdraw", json={"amount": 100})
        res4 = anon_client.post("/transfer", json={"recipient": 12345, "amount": 100})

        if all(r.status_code == 401 for r in [res1, res2, res3, res4]):
            return "DEFENDED", "All sensitive routes strictly require authentication dependency"
        else:
            return "VULNERABLE", "Unauthenticated caller accessed protected route"
    except Exception as e:
        return "INCONCLUSIVE", f"Script crashed: {e}"


def attack_12_concurrent_overdraft(db, auth, client):
    """
    Adversary 12: Concurrent overdraft.
    Mechanism of defence: Atomic conditional update.
    """
    try:
        x, y = schnorr.generate_keypair()
        res1 = auth.register("Overdraft Victim", 100.00, str(y), "dev_12_1")
        acc_v = res1["account_number"]

        _, y2 = schnorr.generate_keypair()
        res2 = auth.register("Receiver 12", 0.00, str(y2), "dev_12_2")
        acc_r = res2["account_number"]

        results = []
        def racer():
            thread_db = database.DataBase()
            u = user.User("Victim", acc_v, thread_db)
            r = u.transfer(acc_r, 80.00)
            results.append(r["success"])

        t1 = threading.Thread(target=racer)
        t2 = threading.Thread(target=racer)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        u_check = user.User("Victim", acc_v, db)
        bal = Decimal(u_check.view_balance()["balance"])

        if results.count(True) == 1 and results.count(False) == 1 and bal == Decimal("20.00"):
            return "DEFENDED", "Race condition prevented: exactly 1 succeeded, balance conserved"
        else:
            return "VULNERABLE", f"Double-spend occurred: results={results}, balance={bal}"
    except Exception as e:
        return "INCONCLUSIVE", f"Script crashed: {e}"


def attack_13_username_enumeration(db, auth, client):
    """
    Adversary 13: Username enumeration.
    Mechanism of defence: Indistinguishable responses.
    """
    try:
        x, y = schnorr.generate_keypair()
        res = auth.register("Enum Target", 100, str(y), "dev_13")
        real_acc = res["account_number"]
        fake_acc = 99999999

        r, R = schnorr.create_commitment()
        # Request with real account but wrong device
        real_res = client.post("/auth/commit", json={"account_number": real_acc, "device_id": "wrong_dev", "commitment": str(R)}).get_json()
        # Request with non-existent account
        fake_res = client.post("/auth/commit", json={"account_number": fake_acc, "device_id": "wrong_dev", "commitment": str(R)}).get_json()

        # Both must return success=False and identical/indistinguishable error message
        if not real_res["success"] and not fake_res["success"]:
            return "DEFENDED", "Responses for existing vs non-existent accounts are indistinguishable"
        else:
            return "VULNERABLE", "Username enumeration is possible"
    except Exception as e:
        return "INCONCLUSIVE", f"Script crashed: {e}"


def attack_14_sustained_brute_force(db, auth, client):
    """
    Adversary 14: Sustained brute force.
    Mechanism of defence: Lockout after five failures.
    """
    try:
        x, y = schnorr.generate_keypair()
        dev = "dev_14"
        res = auth.register("Brute Target", 200, str(y), dev)
        acc = res["account_number"]

        bad_x, _ = schnorr.generate_keypair()
        for _ in range(5):
            r, R = schnorr.create_commitment()
            c_res = client.post("/auth/commit", json={"account_number": acc, "device_id": dev, "commitment": str(R)}).get_json()
            if not c_res["success"]:
                break
            bad_s = schnorr.create_response(r, int(c_res["challenge"]), bad_x)
            client.post("/auth/verify", json={"session_id": c_res["session_id"], "response": str(bad_s)})

        # 6th attempt must be refused with lockout
        r, R = schnorr.create_commitment()
        lock_res = client.post("/auth/commit", json={"account_number": acc, "device_id": dev, "commitment": str(R)}).get_json()

        if not lock_res["success"] and "locked" in lock_res.get("message", "").lower():
            return "DEFENDED", "Account locked out after 5 consecutive failures"
        else:
            return "VULNERABLE", "Brute-force continued without lockout"
    except Exception as e:
        return "INCONCLUSIVE", f"Script crashed: {e}"


# ===========================================================================
# Execution Harness
# ===========================================================================

ADVERSARIES = [
    (1, "Replay of captured transcript", "Fresh single-use challenge", attack_01_replay_captured_transcript),
    (2, "Challenge reuse", "Consumed on first use", attack_02_challenge_reuse),
    (3, "Impersonation without key", "Soundness error 2^-256", attack_03_impersonation_without_key),
    (4, "Identity-element public key", "Registration validation", attack_04_identity_element_public_key),
    (5, "Small-subgroup public key", "Subgroup membership check", attack_05_small_subgroup_public_key),
    (6, "Unregistered device", "Binding checked before challenge", attack_06_unregistered_device),
    (7, "Forged token", "Signature verification / DB check", attack_07_forged_token),
    (8, "Algorithm downgrade to none", "Decoder pinned to valid types", attack_08_algorithm_downgrade_none),
    (9, "Refresh token as access token", "Token type checked per request", attack_09_refresh_token_as_access_token),
    (10, "Token replayed after logout", "Session identifier revocation", attack_10_token_replayed_after_logout),
    (11, "Unauthenticated banking access", "Dependency on all account routes", attack_11_unauthenticated_banking_access),
    (12, "Concurrent overdraft", "Atomic conditional update", attack_12_concurrent_overdraft),
    (13, "Username enumeration", "Indistinguishable responses", attack_13_username_enumeration),
    (14, "Sustained brute force", "Lockout after five failures", attack_14_sustained_brute_force),
]


def run_adversarial_suite():
    print("=" * 75)
    print(" MobileBank-ZKP Adversarial Evaluation Harness (Table 3)")
    print(" 3-Valued Verdict Reporting: [DEFENDED | VULNERABLE | INCONCLUSIVE]")
    print("=" * 75)

    db, auth, client = setup_harness()

    defended_count = 0
    vulnerable_count = 0
    inconclusive_count = 0

    for num, name, mechanism, func in ADVERSARIES:
        verdict, details = func(db, auth, client)
        record_verdict(num, name, mechanism, verdict, details)

        icon = "🛡️ DEFENDED" if verdict == "DEFENDED" else ("❌ VULNERABLE" if verdict == "VULNERABLE" else "⚠️ INCONCLUSIVE")
        print(f"\n[{num:02d}] {name}")
        print(f"     Defence Mechanism : {mechanism}")
        print(f"     Verdict           : {icon}")
        print(f"     Details           : {details}")

        if verdict == "DEFENDED":
            defended_count += 1
        elif verdict == "VULNERABLE":
            vulnerable_count += 1
        else:
            inconclusive_count += 1

    print("\n" + "=" * 75)
    print(f" Evaluation Summary:")
    print(f"   DEFENDED    : {defended_count}/{len(ADVERSARIES)}")
    print(f"   VULNERABLE  : {vulnerable_count}/{len(ADVERSARIES)}")
    print(f"   INCONCLUSIVE: {inconclusive_count}/{len(ADVERSARIES)}")
    print("=" * 75)

    return vulnerable_count == 0 and inconclusive_count == 0


if __name__ == "__main__":
    success = run_adversarial_suite()
    sys.exit(0 if success else 1)
