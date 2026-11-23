"""
test_banking.py — Tests for Phase 5: Transactional Integrity & Session Security.

Tests:
1. Exact Decimal deposit and balance reflection
2. Atomic withdrawal and overdraft prevention
3. Inter-account transfer with Conservation of Value
4. Concurrent transfer race condition test (Table 3: Concurrent Overdraft defence)
5. Session token revocation upon logout (Table 3: Token replayed after logout defence)
6. Unauthenticated banking access rejection (Table 3: Dependency on all account routes)
"""

import sys
import os
import unittest
import threading
from decimal import Decimal

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import database
from services import authentication
from models import user
from crypto import schnorr
from app import app


class TestBankingAndSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = database.DataBase()
        cls.auth = authentication.Authentication(cls.db)

        # Create two test accounts for banking tests
        cls.x1, cls.y1 = schnorr.generate_keypair()
        res1 = cls.auth.register("Sender BankUser", 500.00, str(cls.y1), "dev_bank_1")
        cls.acc1 = res1["account_number"]

        cls.x2, cls.y2 = schnorr.generate_keypair()
        res2 = cls.auth.register("Receiver BankUser", 200.00, str(cls.y2), "dev_bank_2")
        cls.acc2 = res2["account_number"]

    def test_01_deposit_decimal(self):
        """Deposits must update balance with exact decimal arithmetic."""
        u = user.User("Sender BankUser", self.acc1, self.db)
        res = u.deposite(125.50)
        self.assertTrue(res["success"])

        bal_res = u.view_balance()
        self.assertTrue(bal_res["success"])
        self.assertEqual(Decimal(bal_res["balance"]), Decimal("625.50"))

    def test_02_atomic_withdraw_and_overdraft_refusal(self):
        """Withdrawal must debit atomically and refuse amounts exceeding balance."""
        u = user.User("Sender BankUser", self.acc1, self.db)
        # Valid withdraw
        res = u.withdraw(25.50)
        self.assertTrue(res["success"])

        bal = Decimal(u.view_balance()["balance"])
        self.assertEqual(bal, Decimal("600.00"))

        # Overdraft attempt
        overdraft_res = u.withdraw(99999.00)
        self.assertFalse(overdraft_res["success"])
        self.assertIn("insufficient", overdraft_res["message"].lower())

        # Balance remains unchanged
        self.assertEqual(Decimal(u.view_balance()["balance"]), Decimal("600.00"))

    def test_03_transfer_conservation_of_value(self):
        """Transfer must debit sender and credit receiver while conserving total value."""
        u1 = user.User("Sender BankUser", self.acc1, self.db)
        u2 = user.User("Receiver BankUser", self.acc2, self.db)

        bal1_before = Decimal(u1.view_balance()["balance"])
        bal2_before = Decimal(u2.view_balance()["balance"])
        total_before = bal1_before + bal2_before

        res = u1.transfer(self.acc2, 100.00)
        self.assertTrue(res["success"])

        bal1_after = Decimal(u1.view_balance()["balance"])
        bal2_after = Decimal(u2.view_balance()["balance"])
        total_after = bal1_after + bal2_after

        self.assertEqual(bal1_after, bal1_before - Decimal("100.00"))
        self.assertEqual(bal2_after, bal2_before + Decimal("100.00"))
        self.assertEqual(total_before, total_after)

    def test_04_concurrent_overdraft_race_condition(self):
        """
        Table 3: Concurrent Overdraft defence.
        Create an account with $100.
        Launch 2 simultaneous threads each attempting to transfer $80 to another account.
        Exactly ONE must succeed, and the second must be rejected.
        Conservation of value must strictly hold.
        """
        _, y_racer = schnorr.generate_keypair()
        r1 = self.auth.register("Racer One", 100.00, str(y_racer), "dev_race_1")
        acc_racer = r1["account_number"]

        results = []

        def do_transfer():
            db_conn = database.DataBase()
            u = user.User("Racer One", acc_racer, db_conn)
            r = u.transfer(self.acc2, 80.00)
            results.append(r["success"])

        t1 = threading.Thread(target=do_transfer)
        t2 = threading.Thread(target=do_transfer)

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Exactly one must succeed (True), one must fail (False)
        self.assertEqual(results.count(True), 1, f"Expected 1 success, got: {results}")
        self.assertEqual(results.count(False), 1, f"Expected 1 failure, got: {results}")

        # Final balance of racer must be 100 - 80 = 20 (NOT negative or -60)
        u_check = user.User("Racer One", acc_racer, self.db)
        final_bal = Decimal(u_check.view_balance()["balance"])
        self.assertEqual(final_bal, Decimal("20.00"))

    def test_05_session_revocation_on_logout(self):
        """
        Table 3: Token replayed after logout defence.
        A session token must be revoked in active_sessions when logging out.
        Subsequent banking requests using the revoked session must be rejected (401).
        """
        client = app.test_client()

        # Authenticate via 3-move handshake
        r, R = schnorr.create_commitment()
        commit_res = client.post("/auth/commit", json={
            "account_number": self.acc1,
            "device_id": "dev_bank_1",
            "commitment": str(R)
        }).get_json()
        self.assertTrue(commit_res["success"])

        c = int(commit_res["challenge"])
        s = schnorr.create_response(r, c, self.x1)
        verify_res = client.post("/auth/verify", json={
            "session_id": commit_res["session_id"],
            "response": str(s)
        }).get_json()
        self.assertTrue(verify_res["success"])

        # Access banking endpoint while logged in -> 200 OK
        bal_res = client.post("/view_balance")
        self.assertEqual(bal_res.status_code, 200)

        # Logout -> marks session as revoked in active_sessions
        logout_res = client.post("/logout")
        self.assertEqual(logout_res.status_code, 200)

        # Attempt to access banking endpoint again with the same client session -> 401 Unauthorized
        replay_res = client.post("/view_balance")
        self.assertEqual(replay_res.status_code, 401)
        self.assertIn("revoked", replay_res.get_json()["message"].lower())

    def test_06_unauthenticated_banking_access_rejected(self):
        """Table 3: Unauthenticated banking access dependency check."""
        anon_client = app.test_client()
        res = anon_client.post("/transfer", json={"recipient": self.acc2, "amount": 50})
        self.assertEqual(res.status_code, 401)


if __name__ == "__main__":
    unittest.main()
