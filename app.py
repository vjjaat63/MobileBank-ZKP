from flask import Flask, render_template, request, redirect, session, jsonify
from functools import wraps
from services import authentication
from config import database
from models import user
from crypto import schnorr
from dotenv import load_dotenv
import secrets
from datetime import datetime, timedelta
import os

load_dotenv()

db = database.DataBase()
auth = authentication.Authentication(db)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY is not set in the environment")


# ---------------------------------------------------------------------------
# Session & Token Management (Section 4.3 & Table 3)
# ---------------------------------------------------------------------------

def create_session_token(account_number):
    """Generate a revocable bearer session token recorded in active_sessions."""
    token_id = secrets.token_urlsafe(32)
    cur = db.get_cursor()
    if cur:
        try:
            cur.execute(
                """
                INSERT INTO active_sessions (token_id, account_number, token_type, expires_at, revoked)
                VALUES (%s, %s, 'access', NOW() + interval '2 hours', FALSE)
                """,
                (token_id, account_number)
            )
            db.db.commit()
        finally:
            cur.close()
    return token_id


def is_session_valid(token_id, account_number):
    """Check if token is active, not expired, not revoked, and type is 'access'."""
    if not token_id or not account_number:
        return False
    cur = db.get_cursor()
    if not cur:
        return False
    try:
        cur.execute(
            """
            SELECT revoked, expires_at, token_type 
            FROM active_sessions 
            WHERE token_id = %s AND account_number = %s
            """,
            (token_id, account_number)
        )
        row = cur.fetchone()
        if not row:
            return False
        revoked, expires_at, token_type = row
        # Table 3: Token type checked per request (reject refresh token as access token)
        if token_type != 'access':
            return False
        if revoked:
            return False
        if expires_at and expires_at < datetime.now():
            return False
        return True
    finally:
        cur.close()


def login_required(f):
    """Enforces authentication and active session check on all banking routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        acc = session.get("account_number")
        tok = session.get("token_id")
        if not acc or not is_session_valid(tok, acc):
            if request.is_json or request.method == "POST":
                return jsonify({
                    "success": False,
                    "message": "Authentication required or session revoked",
                    "redirect": "/login"
                }), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------------
# Authentication Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')


@app.route("/auth/params", methods=["GET"])
def auth_params():
    """Exposes public group parameters and fingerprint for client key generation."""
    p, q, g = schnorr.get_params()
    return jsonify({
        "p": str(p),
        "q": str(q),
        "g": str(g),
        "fingerprint": schnorr.param_fingerprint()
    })


@app.route("/auth/commit", methods=["POST"])
def auth_commit():
    """Move 1 & 2 of the 3-Move Handshake: Client sends R, receives challenge c."""
    data = request.get_json() or {}
    account_number = data.get("account_number")
    device_id = data.get("device_id")
    commitment = data.get("commitment")
    result = auth.initiate_handshake(account_number, device_id, commitment)
    return jsonify(result)


@app.route("/auth/verify", methods=["POST"])
def auth_verify():
    """Move 3 & Verification: Client sends response s, server verifies g^s ≡ R * y^c."""
    data = request.get_json() or {}
    session_id = data.get("session_id")
    response_s = data.get("response")
    result = auth.verify_response(session_id, response_s)
    if result.get("success"):
        acc = result["account_number"]
        token_id = create_session_token(acc)
        session["account_number"] = acc
        session["name"] = result["name"]
        session["token_id"] = token_id
        result["token_id"] = token_id
    return jsonify(result)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.get_json() or {}
        if "session_id" in data and "response" in data:
            result = auth.verify_response(data.get("session_id"), data.get("response"))
            if result.get("success"):
                acc = result["account_number"]
                token_id = create_session_token(acc)
                session["account_number"] = acc
                session["name"] = result["name"]
                session["token_id"] = token_id
                result["token_id"] = token_id
            return jsonify(result)
        return jsonify({
            "success": False,
            "message": "Password authentication is disabled. Use the Zero-Knowledge handshake."
        })
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.get_json() or {}
        name = data.get("name")
        balance = data.get("balance")
        public_key = data.get("public_key")
        device_id = data.get("device_id")
        result = auth.register(name, balance, public_key, device_id)
        return jsonify(result)
    else:
        return render_template("register.html")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    tok = session.get("token_id")
    if tok:
        cur = db.get_cursor()
        if cur:
            try:
                cur.execute("UPDATE active_sessions SET revoked = TRUE WHERE token_id = %s", (tok,))
                db.db.commit()
            finally:
                cur.close()
    session.clear()
    return {
        "success": True,
        "redirect": "/"
    }


# ---------------------------------------------------------------------------
# Protected Banking Routes (Governed by login_required)
# ---------------------------------------------------------------------------

@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    name = session.get("name", "User")
    return render_template("dashboard.html", name=name)


@app.route("/view_balance", methods=["GET", "POST"])
@login_required
def view_balance():
    name = session["name"]
    account_number = session["account_number"]
    current_user = user.User(name, account_number, db)
    result = current_user.view_balance()
    return jsonify(result)


@app.route("/deposite", methods=["POST"])
@login_required
def deposite():
    data = request.get_json() or {}
    amount = data.get("amount", 0)
    name = session["name"]
    account_number = session["account_number"]
    current_user = user.User(name, account_number, db)
    result = current_user.deposite(amount)
    return jsonify(result)


@app.route("/withdraw", methods=["POST"])
@login_required
def withdraw():
    data = request.get_json() or {}
    amount = data.get("amount", 0)
    name = session["name"]
    account_number = session["account_number"]
    current_user = user.User(name, account_number, db)
    result = current_user.withdraw(amount)
    return jsonify(result)


@app.route("/transaction_history", methods=["POST"])
@login_required
def transaction_history():
    name = session["name"]
    account_number = session["account_number"]
    current_user = user.User(name, account_number, db)
    result = current_user.view_transaction_history()
    return jsonify(result)


@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    data = request.get_json() or {}
    recipient = data.get("recipient")
    amount = data.get("amount")
    name = session["name"]
    account_number = session["account_number"]
    current_user = user.User(name, account_number, db)
    result = current_user.transfer(recipient, amount)
    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True)
