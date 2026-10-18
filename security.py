"""
HealthChain security helpers.

- .env loading (no extra dependency)
- Persistent random Flask SECRET_KEY
- CSRF protection for all state-changing requests
- Security headers (CSP, clickjacking, MIME sniffing, caching, HSTS)
- Login brute-force protection
- Salted password hashing (with transparent upgrade of legacy SHA-256 hashes)
- Input validation helpers
"""

import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from functools import wraps
from urllib.parse import urlparse

from flask import abort, flash, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- .env loader

def load_env(path=None):
    """Load KEY=VALUE pairs from a .env file into os.environ (existing env wins)."""
    path = path or os.path.join(BASE_DIR, '.env')
    if not os.path.exists(path):
        return
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, value = line.partition('=')
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


def env_bool(name, default=False):
    return os.getenv(name, str(default)).strip().lower() in ('1', 'true', 'yes', 'on')


# ---------------------------------------------------------------- secret keys

def _write_private_file(path, data: bytes):
    with open(path, 'wb') as f:
        f.write(data)
    try:
        os.chmod(path, 0o600)  # owner read/write only (no-op on Windows)
    except OSError:
        pass


def get_flask_secret_key():
    """SECRET_KEY from env, otherwise a random key persisted in flask_secret.key."""
    key = os.getenv('SECRET_KEY')
    if key:
        return key
    path = os.path.join(BASE_DIR, 'flask_secret.key')
    if os.path.exists(path):
        with open(path, 'rb') as f:
            return f.read().decode().strip()
    key = secrets.token_hex(32)
    _write_private_file(path, key.encode())
    return key


# ---------------------------------------------------------------- passwords

_LEGACY_SHA256 = re.compile(r'^[0-9a-f]{64}$')
PASSWORD_METHOD = 'pbkdf2:sha256:600000'


def hash_password(password: str) -> str:
    return generate_password_hash(password, method=PASSWORD_METHOD, salt_length=16)


def verify_password(password: str, stored: str) -> bool:
    if not stored:
        return False
    if _LEGACY_SHA256.match(stored):  # old unsalted SHA-256 hash
        legacy = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(legacy, stored)
    try:
        return check_password_hash(stored, password)
    except ValueError:
        return False


def needs_rehash(stored: str) -> bool:
    return bool(_LEGACY_SHA256.match(stored or ''))


USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,50}$')


def validate_username(username: str):
    if not USERNAME_RE.match(username or ''):
        return 'Username must be 3-50 characters: letters, numbers, dot, dash or underscore'
    return None


def validate_password(password: str):
    if len(password) < 8:
        return 'Password must be at least 8 characters'
    if len(password) > 128:
        return 'Password is too long (max 128 characters)'
    if not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password):
        return 'Password must contain at least one letter and one number'
    return None


# ---------------------------------------------------------------- login throttling

class LoginThrottle:
    """In-memory brute-force protection: lock a (ip, username) pair after N failures."""

    def __init__(self, max_attempts=5, lock_seconds=300):
        self.max_attempts = max_attempts
        self.lock_seconds = lock_seconds
        self._failures = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(ip, username):
        return f"{ip}|{(username or '').lower()}"

    def seconds_locked(self, ip, username):
        with self._lock:
            entry = self._failures.get(self._key(ip, username))
            if not entry:
                return 0
            count, first_ts = entry
            if time.time() - first_ts > self.lock_seconds:
                del self._failures[self._key(ip, username)]
                return 0
            if count >= self.max_attempts:
                return int(self.lock_seconds - (time.time() - first_ts)) + 1
            return 0

    def record_failure(self, ip, username):
        with self._lock:
            k = self._key(ip, username)
            count, first_ts = self._failures.get(k, (0, time.time()))
            if time.time() - first_ts > self.lock_seconds:
                count, first_ts = 0, time.time()
            self._failures[k] = (count + 1, first_ts)

    def reset(self, ip, username):
        with self._lock:
            self._failures.pop(self._key(ip, username), None)


login_throttle = LoginThrottle()


# ---------------------------------------------------------------- CSRF

CSRF_EXEMPT_ENDPOINTS = {'receive_block'}  # peer-to-peer JSON, protected by PEER_TOKEN instead


def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


def _csrf_check():
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return
    if request.endpoint in CSRF_EXEMPT_ENDPOINTS:
        return
    expected = session.get('_csrf_token')
    sent = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
    if not expected or not sent or not hmac.compare_digest(expected, sent):
        abort(400, description='Invalid or missing CSRF token. Reload the page and try again.')


# ---------------------------------------------------------------- peer auth

def peer_token_valid():
    """Peer nodes authenticate with a shared secret (PEER_TOKEN). Disabled if unset."""
    expected = os.getenv('PEER_TOKEN', '')
    if not expected:
        return False
    sent = request.headers.get('X-Peer-Token', '')
    return hmac.compare_digest(expected, sent)


def is_valid_peer_url(url: str) -> bool:
    try:
        p = urlparse(url)
    except ValueError:
        return False
    return p.scheme in ('http', 'https') and bool(p.netloc) and not p.username and not p.password \
        and p.path in ('', '/') and not p.query and not p.fragment


# ---------------------------------------------------------------- access control

def login_required(*roles):
    """Require a logged-in user, optionally restricted to given roles."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if roles and session.get('role') not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------- app wiring

CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
    "font-src 'self' https://cdn.jsdelivr.net data:",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])


def init_security(app):
    from datetime import timedelta

    secure_cookie = env_bool('COOKIE_SECURE', False)
    app.config.update(
        SECRET_KEY=get_flask_secret_key(),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=secure_cookie,
        SESSION_COOKIE_NAME='healthchain_session',
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.getenv('SESSION_MINUTES', '30'))),
        MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # 1 MB request cap
    )

    @app.before_request
    def _before():
        _csrf_check()

    @app.context_processor
    def _inject():
        return {'csrf_token': generate_csrf_token}

    @app.after_request
    def _headers(resp):
        resp.headers['Content-Security-Policy'] = CSP
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['Referrer-Policy'] = 'same-origin'
        resp.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
        resp.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        if secure_cookie:
            resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        # Never let browsers/proxies cache dynamic (medical) pages
        if request.endpoint != 'static':
            resp.headers['Cache-Control'] = 'no-store'
            resp.headers['Pragma'] = 'no-cache'
        return resp

    @app.errorhandler(400)
    def _bad_request(e):
        if request.method == 'POST':
            flash(getattr(e, 'description', 'Bad request'))
            return redirect(url_for('index'))
        return 'Bad request', 400

    @app.errorhandler(403)
    def _forbidden(e):
        return 'Forbidden: you do not have permission to access this resource.', 403

    @app.errorhandler(404)
    def _not_found(e):
        return 'Page not found.', 404

    @app.errorhandler(413)
    def _too_large(e):
        return 'Request too large.', 413
