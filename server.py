# server.py — INTENTIONALLY WEAK demo app, LAB USE ONLY
# Isolated network, machines you own. Fake data only.
#
# Demo goal: show that a STOLEN SESSION COOKIE alone lets an attacker
# read sensitive info, move money, and lock out the real user —
# all WITHOUT ever knowing the victim's password.

from flask import Flask, request, redirect, make_response, render_template_string
import secrets

app = Flask(__name__)
SESSIONS = {}  # sessionid -> username

# Fake accounts. Everything here is made up for the demo.
USERS = {
    "alice": {
        "password": "password123",
        "full_name": "Alice Rahman",
        "age": 29,
        "address": "House 14, Road 7, Dhanmondi, Dhaka 1209",
        "phone": "+880 1700-000000",
        "email": "alice@example.com",
        "account_number": "BD91-2040-5567-8812",
        "balance": 9001,
        "transactions": [
            {"desc": "Salary credit",        "amount": +4200},
            {"desc": "Grocery - Agora",      "amount": -85},
            {"desc": "Electricity bill",     "amount": -60},
        ],
    }
}

# ---------- templates ----------

LOGIN_FORM = """
<h2>SecureBank — Login</h2>
<form method="POST">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button>Log in</button>
</form>
"""

ACCOUNT_PAGE = """
<h1>SecureBank — Private Account</h1>
<p><b>Welcome, {{ u.full_name }} (username:@{{ username }}).</b></p>

<h3>Personal details</h3>
<ul>
  <li>Age: {{ u.age }}</li>
  <li>Address: {{ u.address }}</li>
  <li>Phone: {{ u.phone }}</li>
  <li>Email: {{ u.email }}</li>
  <li>Account number: {{ u.account_number }}</li>
</ul>

<h3>Balance: ${{ u.balance }}</h3>

<h3>Recent transactions</h3>
<ul>
  {% for t in u.transactions %}
    <li>{{ t.desc }}: {{ '%+d' % t.amount }}</li>
  {% endfor %}
</ul>

<hr>
<h3>Transfer money</h3>
<form method="POST" action="/transfer">
  <input name="to" placeholder="recipient account">
  <input name="amount" placeholder="amount" type="number">
  <button>Send</button>
</form>

<h3>Change password</h3>
<form method="POST" action="/change_password">
  <input name="new_password" type="password" placeholder="new password">
  <button>Change</button>
</form>
"""

# ---------- helpers ----------

def current_user():
    """Return the username tied to the request's session cookie, or None."""
    return SESSIONS.get(request.cookies.get("sessionid"))

# ---------- routes ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u in USERS and USERS[u]["password"] == p:
            sid = secrets.token_hex(16)
            SESSIONS[sid] = u
            resp = make_response(redirect("/account"))
            resp.set_cookie("sessionid", sid)  # deliberately no Secure/HttpOnly/SameSite
            return resp
        return "Invalid credentials", 401
    return render_template_string(LOGIN_FORM)
@app.route("/account")
def account():
    user = current_user()
    if not user:
        return redirect("/login")
    return render_template_string(ACCOUNT_PAGE, u=USERS[user], username=user)

@app.route("/transfer", methods=["POST"])
def transfer():
    # NOTE: authorized purely by the session cookie — no re-auth, no confirmation.
    # This is exactly what makes a hijacked cookie so dangerous.
    user = current_user()
    if not user:
        return redirect("/login")
    to = request.form.get("to", "unknown")
    try:
        amount = int(request.form.get("amount", "0"))
    except ValueError:
        amount = 0
    acct = USERS[user]
    acct["balance"] -= amount
    acct["transactions"].append({"desc": f"Transfer to {to}", "amount": -amount})
    return redirect("/account")

@app.route("/change_password", methods=["POST"])
def change_password():
    user = current_user()
    if not user:
        return redirect("/login")
    new_pw = request.form.get("new_password", "")
    if new_pw:
        USERS[user]["password"] = new_pw
        # Kill every session for this user, so anyone logged in — including
        # whoever just changed the password — is forced to log in again.
        for sid in [s for s, u in SESSIONS.items() if u == user]:
            del SESSIONS[sid]
    return redirect("/login")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)