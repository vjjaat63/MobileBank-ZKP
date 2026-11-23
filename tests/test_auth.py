"""
test_auth.py — Tests for Phase 3: Registration with Schnorr Public Keys.

Tests:
1. Valid registration with real 3072-bit Schnorr public key
2. Rejection of identity element (y = 1) — prevents total auth bypass
3. Rejection of invalid non-subgroup public key
4. Rejection of negative initial balance
5. Rejection of missing required fields
6. Verification that public key is stored as decimal string without precision loss
"""

import sys
import os
import unittest
from decimal import Decimal

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import database
from services import authentication
from crypto import schnorr


class TestZKPRegistration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = database.DataBase()
        cls.auth = authentication.Authentication(cls.db)

    def test_01_valid_registration(self):
        """A user with a valid Schnorr public key should register successfully."""
        x, y = schnorr.generate_keypair()
        device_id = "test_dev_001"
        res = self.auth.register("Alice ZKP", 500.0, str(y), device_id)
        
        self.assertTrue(res["success"], f"Registration failed: {res.get('message')}")
        self.assertIn("account_number", res)
        acc = res["account_number"]

        # Check DB directly
        cur = self.db.get_cursor()
        cur.execute("SELECT name, balance, public_key, device_id FROM users WHERE account_number = %s", (acc,))
        row = cur.fetchone()
        cur.close()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], "Alice ZKP")
        self.assertEqual(Decimal(str(row[1])), Decimal("500.00"))
        self.assertEqual(row[2], str(y))
        self.assertEqual(row[3], device_id)

    def test_02_reject_identity_element(self):
        """Registration with y=1 MUST be rejected (prevents auth bypass)."""
        res = self.auth.register("Attacker", 100.0, "1", "evil_device")
        self.assertFalse(res["success"])
        self.assertIn("rejected", res["message"].lower())

    def test_03_reject_non_subgroup_element(self):
        """Registration with a number not in order-q subgroup must be rejected."""
        p, q, _ = schnorr.get_params()
        # 3 is not in the subgroup
        res = self.auth.register("Bob", 100.0, "3", "dev_002")
        self.assertFalse(res["success"])
        self.assertIn("rejected", res["message"].lower())

    def test_04_reject_negative_deposit(self):
        """Initial deposit cannot be negative."""
        _, y = schnorr.generate_keypair()
        res = self.auth.register("Charlie", -50.0, str(y), "dev_003")
        self.assertFalse(res["success"])
        self.assertIn("negative", res["message"].lower())

    def test_05_reject_missing_fields(self):
        """Missing public key or device ID must be rejected."""
        res = self.auth.register("Dave", 100.0, "", "dev_004")
        self.assertFalse(res["success"])

        res2 = self.auth.register("Dave", 100.0, "12345", "")
        self.assertFalse(res2["success"])


if __name__ == "__main__":
    unittest.main()
