# server_hardened.py — MITIGATED version of the demo app, LAB USE ONLY
# Isolated network, machines you own. Fake data only.
#
# Demo goal (Section 5): show that the SAME ARP poisoning still works,
# but sidejacking now FAILS because the session cookie never crosses
# the wire in cleartext.
#
# Three changes vs. server.py:
#   1. sessionid cookie carries Secure + HttpOnly + SameSite=Strict
#   2. Strict-Transport-Security header on every response
#   3. app.run() serves TLS on 443 instead of plaintext on 80
#
# Before running, generate a self-signed cert in this directory:
#   openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 30 \
#     -subj "/CN=<server-ip>"

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
<p><b>Welcome, {{ u.full_name }}.</b></p>

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

# ---------- mitigation 2: HSTS on every response ----------

@app.after_request
def hsts(resp):
    # Tells a conforming browser to refuse plaintext HTTP to this origin for a year.
    # NOTE: browsers ignore this header when the host is a bare IP address, and when
    # the certificate is untrusted — so in this lab it is configuration evidence,
    # not an enforced control. The confidentiality win comes from TLS itself.
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp

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
            # ---------- mitigation 1: harden the cookie ----------
            #   secure=True    -> never transmitted over plaintext HTTP
            #   httponly=True  -> unreadable from document.cookie (blocks XSS theft)
            #   samesite=Strict-> not attached to cross-site requests (blocks CSRF)
            resp.set_cookie("sessionid", sid, secure=True, httponly=True, samesite="Strict")
            return resp
        return "Invalid credentials", 401
    return render_template_string(LOGIN_FORM)

@app.route("/account")
def account():
    user = current_user()
    if not user:
        return redirect("/login")
    return render_template_string(ACCOUNT_PAGE, u=USERS[user])

@app.route("/transfer", methods=["POST"])
def transfer():
    # Still authorized purely by the session cookie. Deliberately unchanged:
    # the point of Section 5 is that TLS removes the attacker's ability to
    # OBTAIN the cookie, not that the app got better at checking it.
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
    return redirect("/account")

# ---------- mitigation 3: serve TLS ----------

if __name__ == "__main__":
    # Port 443 requires root: sudo python3 server_hardened.py
    # Without root, use 8443 and browse to https://<server-ip>:8443
    # (match your sniffer filter to whichever port you pick).
    app.run(host="0.0.0.0", port=443, ssl_context=("cert.pem", "key.pem"))