"""Settings for SecureShop. Secrets come from environment variables, never from the code."""
import os
import secrets
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # SECURITY: the secret key signs the session cookie. Read it from the environment.
    # If it is missing we make a random one (fine for development, but everyone is logged
    # out each time the app restarts).
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "secureshop.db"))
    # Wait up to 15 s if another request is writing (SQLite locks the file while writing).
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"timeout": 15}}

    # SECURITY: session cookie flags.
    SESSION_COOKIE_HTTPONLY = True        # JavaScript cannot read the cookie (limits XSS damage)
    SESSION_COOKIE_SAMESITE = "Lax"       # cookie is not sent on cross-site POSTs (helps vs CSRF)
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"  # set to 1 when using HTTPS
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)                  # idle sessions expire

    # SECURITY: CSRF tokens on every POST form (Flask-WTF), valid for 1 hour.
    WTF_CSRF_TIME_LIMIT = 3600

    # Reject request bodies bigger than 1 MB.
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024

    # Login lockout rules.
    MAX_FAILED_LOGINS = 5
    LOCKOUT_MINUTES = 15
