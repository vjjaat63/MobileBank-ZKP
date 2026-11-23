"""
test_handshake.py — Tests for Phase 4: 3-Move Schnorr Authentication Handshake.

Tests:
1. Complete honest handshake (Move 1 -> Move 2 -> Move 3 -> Verified)
2. Refusal of wrong private key (Soundness error)
3. Refusal of challenge reuse / replay (Single-use consumption)
4. Refusal of unregistered device (Device binding check)
5. Sustained brute force lockout (Lockout after 5 failed attempts)
6. Indistinguishable response on non-existent account (Prevents username enumeration)
7. Full HTTP integration test via Flask client
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import database
from services import authentication
from crypto import schnorr
from app import app


class TestZKPHandshake(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = database.DataBase()
        cls.auth = authentication.Authentication(cls.db)

        # Register a primary test user
        cls.x, cls.y = schnorr.generate_keypair()
        cls.device_id = "test_device_handshake_1"
        res = cls.auth.register("Handshake Alice", 1000.0, str(cls.y), cls.device_id)
        assert res["success"], f"Failed to register test user: {res}"
        cls.acc = res["account_number"]

    def test_01_honest_handshake_success(self):
        """Honest prover with genuine private key completes handshake."""
        # Move 1: Prover creates commitment
        r, R = schnorr.create_commitment()
        commit_res = self.auth.initiate_handshake(self.acc, self.device_id, str(R))
        self.assertTrue(commit_res["success"], f"Commit failed: {commit_res}")
        self.assertIn("session_id", commit_res)
        self.assertIn("challenge", commit_res)

        session_id = commit_res["session_id"]
        c = int(commit_res["challenge"])

        # Move 3: Prover computes response
        s = schnorr.create_response(r, c, self.x)
        verify_res = self.auth.verify_response(session_id, str(s))

        self.assertTrue(verify_res["success"], f"Verification failed: {verify_res}")
        self.assertEqual(verify_res["account_number"], self.acc)
        self.assertEqual(verify_res["name"], "Handshake Alice")

    def test_02_wrong_private_key_fails(self):
        """Attacker using a different private key must fail verification."""
        attacker_x, _ = schnorr.generate_keypair()

        r, R = schnorr.create_commitment()
        commit_res = self.auth.initiate_handshake(self.acc, self.device_id, str(R))
        self.assertTrue(commit_res["success"])

        session_id = commit_res["session_id"]
        c = int(commit_res["challenge"])

        # Attacker responds with wrong key
        bad_s = schnorr.create_response(r, c, attacker_x)
        verify_res = self.auth.verify_response(session_id, str(bad_s))

        self.assertFalse(verify_res["success"])
        self.assertIn("failed", verify_res["message"].lower())

    def test_03_challenge_replay_prevented(self):
        """Replaying a captured response with the same session_id must fail."""
        r, R = schnorr.create_commitment()
        commit_res = self.auth.initiate_handshake(self.acc, self.device_id, str(R))
        session_id = commit_res["session_id"]
        c = int(commit_res["challenge"])
        s = schnorr.create_response(r, c, self.x)

        # First use: succeeds
        res1 = self.auth.verify_response(session_id, str(s))
        self.assertTrue(res1["success"])

        # Replay attempt: must fail because session_id was deleted upon first use
        res2 = self.auth.verify_response(session_id, str(s))
        self.assertFalse(res2["success"])
        self.assertIn("invalid", res2["message"].lower())

    def test_04_unregistered_device_rejected(self):
        """Request from an unbound/unregistered device must be rejected."""
        r, R = schnorr.create_commitment()
        res = self.auth.initiate_handshake(self.acc, "unregistered_rogue_phone", str(R))
        self.assertFalse(res["success"])
        self.assertIn("device", res["message"].lower())

    def test_05_sustained_brute_force_lockout(self):
        """Account must lock after 5 consecutive failed attempts."""
        # Create a fresh account to test lockout
        x_lock, y_lock = schnorr.generate_keypair()
        dev_lock = "lockout_device_1"
        res = self.auth.register("Lockout Bob", 100.0, str(y_lock), dev_lock)
        acc_lock = res["account_number"]

        bad_x, _ = schnorr.generate_keypair()

        # Fail 5 times
        for attempt in range(5):
            r, R = schnorr.create_commitment()
            c_res = self.auth.initiate_handshake(acc_lock, dev_lock, str(R))
            self.assertTrue(c_res["success"], f"Handshake failed at attempt {attempt}")
            c = int(c_res["challenge"])
            bad_s = schnorr.create_response(r, c, bad_x)
            v_res = self.auth.verify_response(c_res["session_id"], str(bad_s))
            self.assertFalse(v_res["success"])

        # 6th attempt: handshake initiation itself must be refused due to lockout
        r, R = schnorr.create_commitment()
        lock_res = self.auth.initiate_handshake(acc_lock, dev_lock, str(R))
        self.assertFalse(lock_res["success"])
        self.assertIn("locked", lock_res["message"].lower())

    def test_06_non_existent_account_indistinguishable(self):
        """Non-existent account yields indistinguishable error without leaking info."""
        r, R = schnorr.create_commitment()
        res = self.auth.initiate_handshake(99999999, "any_device", str(R))
        self.assertFalse(res["success"])

    def test_07_http_end_to_end_login(self):
        """End-to-end login through Flask HTTP client."""
        client = app.test_client()

        # Step 1: Commitment
        r, R = schnorr.create_commitment()
        r1 = client.post("/auth/commit", json={
            "account_number": self.acc,
            "device_id": self.device_id,
            "commitment": str(R)
        })
        self.assertEqual(r1.status_code, 200)
        data1 = r1.get_json()
        self.assertTrue(data1["success"])

        session_id = data1["session_id"]
        c = int(data1["challenge"])

        # Step 2: Response & Verification
        s = schnorr.create_response(r, c, self.x)
        r2 = client.post("/auth/verify", json={
            "session_id": session_id,
            "response": str(s)
        })
        self.assertEqual(r2.status_code, 200)
        data2 = r2.get_json()
        self.assertTrue(data2["success"])


if __name__ == "__main__":
    unittest.main()
