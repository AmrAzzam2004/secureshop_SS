# SecureShop – CET431 Software Security (Phase 1)

A small online shop built with Python + Flask, defended against the common web attacks.
Simple on purpose: plain HTML pages, no JavaScript, SQLite database.

## 1. Setup (Windows, macOS or Linux)

You need **Python 3.11+**.

```bash
cd secureshop
python -m venv .venv
# Windows:  .venv\Scripts\activate        macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
python seed.py            # creates the database with sample data
python run.py             # open http://127.0.0.1:5000
```

Optional: set a fixed secret key so logins survive restarts
(Windows: `set SECRET_KEY=some-long-random-text`, macOS/Linux: `export SECRET_KEY=...`).

Run the automatic security tests: `python -m pytest -q` (18 tests).

## 2. Test accounts

| Role | Email | Password | Store credit |
|---|---|---|---|
| Admin |  | Admin#Pass2026 | $500 |
| Customer | user@secureshop.local | User#Pass2026 | $100 |
| Customer 2 (for IDOR tests) | user2@secureshop.local | User2#Pass2026 | $100 |

Coupon for everyone: `WELCOME10` (10% off). Newsletter signup gives each account its own one-time coupon.

**Email confirmation:** there is no mail server. When someone registers, the confirmation link
is printed in the terminal and saved in `emails.log`. Open that link to confirm the account.

## 3. Architecture overview

```
Browser ──HTTP──► Flask app (app/__init__.py)
                   │  global protections: CSRF tokens, security headers, error pages, session rules
                   ├── auth.py       register, confirm, login, logout            (Blue 1)
                   ├── account.py    profile, password change, my orders         (Blue 1)
                   ├── catalogue.py  product list, detail, search, filter        (Blue 2)
                   ├── cart.py       cart in the session (ids + quantities only) (Blue 2)
                   ├── shop.py       newsletter, coupons, checkout, order pages  (Blue 3)
                   ├── admin.py      users, products, coupons, security log      (Blue 2 + 3)
                   ├── security.py   password hashing, tokens, input checks, audit log
                   └── models.py ──SQLAlchemy ORM──► SQLite (secureshop.db)
```

- **Templates** (`app/templates/`): Jinja2 HTML, which escapes all output automatically.
- **Money** is stored as whole cents (integers).
- **Sessions**: signed cookie (HttpOnly, SameSite=Lax, 30-minute lifetime) holding `user_id:session_token`.
  The token changes on logout and password change, so stolen copies of the cookie stop working.

## 4. Where each defense is in the code (for the Security Coverage Matrix)

| Attack | Defense | Where |
|---|---|---|
| SQL injection | ORM with parameters, `<int:id>` routes | `catalogue.py: products()`, all queries |
| XSS | Jinja2 auto-escaping (the `safe` filter is never used on user data), CSP header without inline scripts | templates, `__init__.py: security_headers()` |
| CSRF | Token on every POST form, SameSite cookie, logout is POST | `__init__.py` (CSRFProtect), every form in templates |
| Brute force / user enumeration | Lockout after 5 failures, same error message, dummy hash timing, same register message | `auth.py: login(), register()` |
| Password storage | argon2id with salt; strength check | `security.py: hash_password(), password_problem()` |
| Session fixation / hijacking | `session.clear()` on login, session token rotated on logout, cookie flags, 30-min expiry | `auth.py: login(), logout()`, `__init__.py: load_user()`, `config.py` |
| Confirmation tokens | Random 32-byte token, stored hashed, 24 h expiry, single use | `auth.py: register(), confirm()` |
| IDOR | Orders looked up by id **and** owner | `shop.py: order_detail()`, `account.py: profile()` |
| Admin access / privilege escalation | `before_request` check on every admin route (deny by default) | `admin.py: admin_only()` |
| Mass assignment / tampering | Only allowed fields read; prices always from the database | `account.py: profile()`, `cart.py`, `shop.py: place_order()` |
| Business logic | Quantity 1–10 and ≤ stock, one coupon per order, coupon rules, newsletter tied to account | `cart.py`, `shop.py: check_coupon(), newsletter()` |
| Race conditions | Atomic conditional UPDATEs in one transaction; DB unique/check constraints | `shop.py: place_order()`, `models.py` |
| Input validation | Type, range and length checks on every field | `security.py: to_int(), to_cents()`, each route |
| Open redirect | `next=` allowed only for local paths | `security.py: is_safe_next()` |
| Misconfiguration / info leak | Debug off, custom error pages, secret from environment | `run.py`, `__init__.py`, `config.py` |
| Clickjacking / headers | `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, nosniff, Referrer-Policy | `__init__.py: security_headers()` |
| Logging | Logins, failures, lockouts, orders, admin actions, blocked admin access | `security.py: audit()`, admin dashboard |

Automatic proof for most rows: `tests/test_security.py`.

## 5. Libraries used (cited)

Flask, Flask-SQLAlchemy, Flask-Login, Flask-WTF (CSRF), argon2-cffi, pytest – see `requirements.txt`.
