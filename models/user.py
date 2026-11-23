from config import database
from decimal import Decimal, InvalidOperation

class User():
    def __init__(self, name, account_number, db):
        self.name = name
        self.account_number = int(account_number)
        self.db = db

    def __str__(self):
        return f"{self.name} || Account Number: {self.account_number}"

    def deposite(self, amount):
        """
        Deposit funds using exact fixed-point Decimal arithmetic.
        """
        try:
            amt = Decimal(str(amount))
            if amt <= 0:
                return {
                    "success": False,
                    "message": "Amount must be greater than zero"
                }
        except (InvalidOperation, TypeError, ValueError):
            return {
                "success": False,
                "message": "Invalid amount format"
            }

        cursor = self.db.get_cursor()
        if not cursor:
            return {"success": False, "message": "Database connection error"}
        try:
            query = "UPDATE users SET balance = balance + %s WHERE account_number = %s"
            cursor.execute(query, (amt, self.account_number))
            if cursor.rowcount == 0:
                self.db.db.rollback()
                return {"success": False, "message": "Account not found"}

            query = "INSERT INTO transactions (to_account, amount, transaction_type) VALUES (%s, %s, %s)"
            cursor.execute(query, (self.account_number, amt, "Deposite"))
            self.db.db.commit()
            return {
                "success": True,
                "message": f"${amt:.2f} successfully deposited to account number {self.account_number}"
            }
        except Exception as e:
            self.db.db.rollback()
            return {
                "success": False,
                "message": f"Deposit failed: {str(e)}"
            }
        finally:
            cursor.close()

    def withdraw(self, amount):
        """
        Withdraw funds using ATOMIC CONDITIONAL UPDATE (Section 4.5).
        
        UPDATE users SET balance = balance - :amount 
        WHERE account_number = :account_number AND balance >= :amount
        
        Eliminates race conditions and concurrent overdrafts by combining the sufficiency
        check and the write into a single atomic database operation.
        """
        try:
            amt = Decimal(str(amount))
            if amt <= 0:
                return {
                    "success": False,
                    "message": "Amount must be greater than zero"
                }
        except (InvalidOperation, TypeError, ValueError):
            return {
                "success": False,
                "message": "Invalid amount format"
            }

        cursor = self.db.get_cursor()
        if not cursor:
            return {"success": False, "message": "Database connection error"}
        try:
            # Atomic conditional update
            query = "UPDATE users SET balance = balance - %s WHERE account_number = %s AND balance >= %s"
            cursor.execute(query, (amt, self.account_number, amt))

            if cursor.rowcount == 0:
                self.db.db.rollback()
                return {
                    "success": False,
                    "message": "Insufficient balance or account not found"
                }

            query = "INSERT INTO transactions (from_account, amount, transaction_type) VALUES (%s, %s, %s)"
            cursor.execute(query, (self.account_number, amt, "Withdrawn"))
            self.db.db.commit()
            return {
                "success": True,
                "message": f"${amt:.2f} successfully withdrawn from account number {self.account_number}"
            }
        except Exception as e:
            self.db.db.rollback()
            return {
                "success": False,
                "message": f"Withdrawal failed: {str(e)}"
            }
        finally:
            cursor.close()

    def transfer(self, other, amount):
        """
        Inter-account transfer with ATOMIC CONDITIONAL DEBIT (Section 4.5).
        
        Guarantees Conservation of Value under high concurrency:
        1. Recipient existence check.
        2. Atomic conditional debit on sender:
           UPDATE users SET balance = balance - :amount WHERE id = :sender AND balance >= :amount
        3. If sender matches 0 rows (loses race or insufficient funds), transfer is immediately refused.
        4. Recipient is credited and transaction is logged in an atomic transaction.
        """
        try:
            amt = Decimal(str(amount))
            if amt <= 0:
                return {
                    "success": False,
                    "message": "Amount must be greater than zero"
                }
        except (InvalidOperation, TypeError, ValueError):
            return {
                "success": False,
                "message": "Invalid amount format"
            }

        try:
            recipient = int(other)
        except (TypeError, ValueError):
            return {
                "success": False,
                "message": "Invalid recipient account number"
            }

        if recipient == self.account_number:
            return {
                "success": False,
                "message": "Cannot transfer to your own account"
            }

        cursor = self.db.get_cursor()
        if not cursor:
            return {"success": False, "message": "Database connection error"}
        try:
            # 1. Verify recipient existence
            cursor.execute("SELECT 1 FROM users WHERE account_number = %s", (recipient,))
            if not cursor.fetchone():
                return {
                    "success": False,
                    "message": "Recipient account does not exist"
                }

            # 2. Atomic conditional debit on sender
            debit_query = "UPDATE users SET balance = balance - %s WHERE account_number = %s AND balance >= %s"
            cursor.execute(debit_query, (amt, self.account_number, amt))

            if cursor.rowcount == 0:
                self.db.db.rollback()
                return {
                    "success": False,
                    "message": "Insufficient balance"
                }

            # 3. Credit recipient
            credit_query = "UPDATE users SET balance = balance + %s WHERE account_number = %s"
            cursor.execute(credit_query, (amt, recipient))

            # 4. Insert transaction ledger record
            tx_query = "INSERT INTO transactions (from_account, to_account, amount, transaction_type) VALUES (%s, %s, %s, %s)"
            cursor.execute(tx_query, (self.account_number, recipient, amt, "Transfer"))

            self.db.db.commit()
            return {
                "success": True,
                "message": f"${amt:.2f} successfully transferred to account number {recipient}"
            }
        except Exception as e:
            self.db.db.rollback()
            return {
                "success": False,
                "message": f"Transfer failed: {str(e)}"
            }
        finally:
            cursor.close()

    def view_balance(self):
        cursor = self.db.get_cursor()
        if not cursor:
            return {"success": False, "message": "Database connection error"}
        try:
            query = "SELECT balance FROM users WHERE account_number = %s"
            cursor.execute(query, (self.account_number,))
            row = cursor.fetchone()
            if row is None:
                return {"success": False, "message": "Account not found"}
            bal = Decimal(str(row[0]))
            return {
                "success": True,
                "balance": str(bal),
                "message": f"Your current balance is: ${bal:.2f}"
            }
        except Exception as e:
            return {
                "success": False,
                "message": f"Unable to fetch balance: {str(e)}"
            }
        finally:
            cursor.close()

    def view_transaction_history(self):
        cursor = self.db.get_cursor()
        if not cursor:
            return {"success": False, "message": "Database connection error"}
        try:
            query = """
                SELECT transaction_id, from_account, to_account, amount, transaction_date, transaction_type 
                FROM transactions 
                WHERE from_account = %s OR to_account = %s 
                ORDER BY transaction_date DESC
            """
            cursor.execute(query, (self.account_number, self.account_number))
            history = cursor.fetchall()
            transactions = []
            for i in history:
                if i[5] == "Transfer" and i[1] == self.account_number:
                    transaction_type = "Sent"
                elif i[5] == "Transfer" and i[2] == self.account_number:
                    transaction_type = "Received"
                else:
                    transaction_type = i[5]
                transactions.append({
                    "Transaction_id": i[0],
                    "Sender": i[1],
                    "Receipent": i[2],
                    "Amount": str(Decimal(str(i[3]))),
                    "Date": str(i[4]),
                    "Type": transaction_type
                })
            return {
                "success": True,
                "data": transactions
            }
        except Exception as e:
            return {
                "success": False,
                "message": "Unable to fetch transaction history"
            }
        finally:
            cursor.close()
