from config import database
from utils import utils
from crypto import schnorr
from decimal import Decimal
import secrets
from datetime import datetime, timedelta
import os

class Authentication():
    def __init__(self, db):
        self.db = db

    def register(self, name, balance, public_key, device_id):
        """
        Register a new user using Schnorr Zero-Knowledge public key.
        Section 4.2 of MobileBank-ZKP.
        """
        cursor = self.db.get_cursor()
        if not cursor:
            return {
                "success": False,
                "message": "Database connection error"
            }
        try:
            if not name or balance is None or not public_key or not device_id:
                return {
                    "success": False,
                    "message": "Name, initial balance, public key, and device ID are required"
                }

            try:
                bal = Decimal(str(balance))
                if bal < 0:
                    return {
                        "success": False,
                        "message": "Initial deposit cannot be negative"
                    }
            except Exception:
                return {
                    "success": False,
                    "message": "Invalid balance format"
                }

            # Decimal string parsing for large 3072-bit integer (Section 4.4)
            try:
                y = int(str(public_key).strip())
            except ValueError:
                return {
                    "success": False,
                    "message": "Invalid public key: must be a decimal integer string"
                }

            # Validate public key mathematically (reject identity element y=1 & subgroup attacks)
            if not schnorr.validate_public_key(y):
                return {
                    "success": False,
                    "message": "Invalid public key: rejected by cryptographic subgroup validation"
                }

            # Generate unique account number
            while True:
                account_number = utils.generate_account_number()
                query = "SELECT 1 FROM users WHERE account_number = %s"
                cursor.execute(query, (account_number,))
                if not cursor.fetchone():
                    break

            try:
                query = """
                    INSERT INTO users (name, account_number, balance, public_key, device_id, failed_attempts) 
                    VALUES (%s, %s, %s, %s, %s, 0)
                """
                cursor.execute(query, (name.strip(), account_number, bal, str(y), str(device_id).strip()))
                self.db.db.commit()
                return {
                    "success": True,
                    "account_number": account_number,
                    "message": f"Registration Successful! Your account number is: {account_number}"
                }
            except Exception as e:
                self.db.db.rollback()
                return {
                    "success": False,
                    "message": f"Registration failed: {str(e)}"
                }
        finally:
            cursor.close()

    def initiate_handshake(self, account_number, device_id, commitment):
        """
        Move 1 & 2 of the Schnorr ZKP Handshake (Section 4.3):
        - Receives account_number, device_id, commitment R
        - Checks account lockout status
        - Verifies device binding
        - Validates commitment R subgroup membership
        - Issues single-use 256-bit challenge c indexed by unguessable session_id
        """
        cursor = self.db.get_cursor()
        if not cursor:
            return {"success": False, "message": "Database connection error"}
        try:
            try:
                acc = int(account_number)
            except (ValueError, TypeError):
                return {"success": False, "message": "Invalid account number"}

            cursor.execute(
                "SELECT name, public_key, device_id, failed_attempts, locked_until FROM users WHERE account_number = %s",
                (acc,)
            )
            user_row = cursor.fetchone()
            if not user_row:
                # Table 3: Indistinguishable response prevents username enumeration
                return {"success": False, "message": "Authentication failed: invalid credentials or device"}

            name, public_key, reg_device, failed_attempts, locked_until = user_row
            failed_attempts = failed_attempts or 0

            # Lockout check
            if locked_until and locked_until > datetime.now():
                rem = int((locked_until - datetime.now()).total_seconds())
                return {
                    "success": False,
                    "message": f"Account is temporarily locked due to repeated failures. Try again in {max(1, rem)} seconds."
                }

            # Device binding check (checked BEFORE cryptographic work)
            if not device_id or str(device_id).strip() != str(reg_device).strip():
                new_fails = failed_attempts + 1
                if new_fails >= 5:
                    cursor.execute(
                        "UPDATE users SET failed_attempts = %s, locked_until = NOW() + interval '5 minutes' WHERE account_number = %s",
                        (new_fails, acc)
                    )
                else:
                    cursor.execute(
                        "UPDATE users SET failed_attempts = %s WHERE account_number = %s",
                        (new_fails, acc)
                    )
                self.db.db.commit()
                return {"success": False, "message": "Authentication failed: unrecognized device"}

            # Validate commitment R
            try:
                R_int = int(str(commitment).strip())
            except (ValueError, TypeError):
                return {"success": False, "message": "Invalid commitment: must be decimal string"}

            p, q, _ = schnorr.get_params()
            if R_int <= 1 or R_int >= p - 1 or pow(R_int, q, p) != 1:
                return {"success": False, "message": "Invalid commitment: subgroup validation failed"}

            # Clean expired challenges (> 120 seconds)
            cursor.execute("DELETE FROM pending_challenges WHERE created_at < NOW() - interval '120 seconds'")

            # Move 2: generate 256-bit challenge c and unguessable session_id
            c = schnorr.generate_challenge()
            session_id = secrets.token_urlsafe(32)

            cursor.execute(
                """
                INSERT INTO pending_challenges (session_id, username, device_id, commitment, challenge, created_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
                """,
                (session_id, acc, str(device_id).strip(), str(R_int), str(c))
            )
            self.db.db.commit()

            return {
                "success": True,
                "session_id": session_id,
                "challenge": str(c)
            }
        except Exception as e:
            self.db.db.rollback()
            return {"success": False, "message": f"Handshake initiation failed: {str(e)}"}
        finally:
            cursor.close()

    def verify_response(self, session_id, response_s):
        """
        Move 3 & Verification (Section 4.3):
        - Retrieves challenge by session_id
        - CONSUMES challenge immediately (single-use defence against replay)
        - Verifies Schnorr equation: g^s ≡ R * y^c (mod p)
        - Resets lockout on success; locks account after 5 sustained failures
        """
        cursor = self.db.get_cursor()
        if not cursor:
            return {"success": False, "message": "Database connection error"}
        try:
            if not session_id or response_s is None:
                return {"success": False, "message": "Session ID and response are required"}

            # Lookup pending challenge
            cursor.execute(
                """
                SELECT username, device_id, commitment, challenge, created_at
                FROM pending_challenges
                WHERE session_id = %s
                """,
                (session_id,)
            )
            row = cursor.fetchone()

            # SINGLE-USE CONSUMPTION: delete challenge immediately
            cursor.execute("DELETE FROM pending_challenges WHERE session_id = %s", (session_id,))
            self.db.db.commit()

            if not row:
                return {"success": False, "message": "Invalid, expired, or already used authentication session"}

            acc, dev_id, R_str, c_str, created_at = row

            # Check 120-second expiration window
            if created_at and (datetime.now() - created_at).total_seconds() > 120:
                return {"success": False, "message": "Authentication challenge expired (120s limit exceeded)"}

            # Lookup user's registered public key
            cursor.execute(
                "SELECT name, public_key, failed_attempts, locked_until FROM users WHERE account_number = %s",
                (acc,)
            )
            user_row = cursor.fetchone()
            if not user_row:
                return {"success": False, "message": "User not found"}

            name, pub_key_str, failed_attempts, locked_until = user_row
            failed_attempts = failed_attempts or 0

            if locked_until and locked_until > datetime.now():
                return {"success": False, "message": "Account is locked"}

            # Parse numbers
            try:
                s_int = int(str(response_s).strip())
                R_int = int(R_str)
                c_int = int(c_str)
                y_int = int(pub_key_str)
            except (ValueError, TypeError):
                return {"success": False, "message": "Malformed response numbers"}

            _, q, _ = schnorr.get_params()
            if s_int < 0 or s_int >= q:
                return {"success": False, "message": "Response out of valid subgroup range"}

            # VERIFY SCHNORR EQUATION: g^s ≡ R * y^c (mod p)
            is_valid = schnorr.verify(R_int, c_int, s_int, y_int)

            if is_valid:
                # Reset failed attempts and lockout on success
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE account_number = %s",
                    (acc,)
                )
                self.db.db.commit()
                return {
                    "success": True,
                    "account_number": acc,
                    "name": name,
                    "message": "Login Successful via Schnorr Zero-Knowledge Proof"
                }
            else:
                # Failure: increment failed attempts and trigger lockout if >= 5
                new_fails = failed_attempts + 1
                if new_fails >= 5:
                    cursor.execute(
                        "UPDATE users SET failed_attempts = %s, locked_until = NOW() + interval '5 minutes' WHERE account_number = %s",
                        (new_fails, acc)
                    )
                else:
                    cursor.execute(
                        "UPDATE users SET failed_attempts = %s WHERE account_number = %s",
                        (new_fails, acc)
                    )
                self.db.db.commit()
                return {
                    "success": False,
                    "message": "Zero-Knowledge proof verification failed"
                }
        finally:
            cursor.close()
