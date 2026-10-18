# HealthChain - Secure Health Records Management

Flask app for patients, doctors and admins. Medical records are encrypted, digitally signed
and anchored on a hash chain (optionally on Ethereum/Ganache).

## Quick start

1. Install Python 3.10+ and MySQL 8, make sure MySQL is running.
2. Create a virtual environment and install dependencies:
   ```
   python -m venv venv
   venv\Scripts\activate          (Windows)   |   source venv/bin/activate   (Linux/Mac)
   pip install -r requirements.txt
   ```
3. Copy `.env.example` to `.env` and set `DB_PASSWORD` (your MySQL root password).
4. Create the first admin account (admins cannot self-register):
   ```
   python create_admin.py
   ```
5. Start the app and open http://127.0.0.1:5000
   ```
   python app.py            (or: python app.py 5001  to choose another port)
   ```

The database, tables, signing keys and blockchain file are created automatically on first run.

## Security features

| Area | Protection |
|------|-----------|
| Passwords | Salted PBKDF2-SHA256 (600k iterations). Old SHA-256 hashes are upgraded at next login. Min 8 chars, letter + number. |
| Sessions | HttpOnly, SameSite=Lax cookies, optional Secure flag, random persisted secret key, 30 min idle timeout, session reset on login. |
| CSRF | Every POST requires a per-session token. |
| Brute force | 5 failed logins per IP+username -> 5 minute lock. |
| Access control | Role checks on every route; admin-only: peers, resolve, reset, API info. Records/requests restricted to their owner (no IDOR). |
| Admin accounts | Not available in the public register form - created with `create_admin.py`. |
| Data at rest | Medical records encrypted per patient (Fernet). Patient keys and doctor RSA private keys are encrypted with a master key (`secret.key` / `HEALTHCHAIN_ENCRYPTION_KEY`). |
| Integrity | RSA signatures + SHA-256 hash chain; peer blocks accepted only with `PEER_TOKEN`. |
| Headers | CSP, X-Frame-Options, nosniff, Referrer-Policy, no-store caching, HSTS (when HTTPS). |
| Misc | SQL is fully parameterised, no stack traces/errors exposed, 1 MB request limit, listens on 127.0.0.1 by default. |

## Going to production

* Serve over **HTTPS** (nginx / Caddy reverse proxy) and set `COOKIE_SECURE=true`.
* Run with a real WSGI server, e.g. `pip install waitress` then
  `waitress-serve --host 127.0.0.1 --port 5000 app:app`.
  (If you use waitress, call `init_database()` once first, e.g. by running `python app.py` once.)
* Use a dedicated MySQL user (not root) with rights only on the `healthchain` database.
* Back up `secret.key` - without it encrypted keys in the database cannot be recovered.
  Never commit `.env`, `secret.key` or `flask_secret.key`.

## Peer nodes (optional)

Set the same `PEER_TOKEN` in `.env` on every node, then log in as admin and open `/add_peer`.
