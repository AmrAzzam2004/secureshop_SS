"""Small security helpers shared by all features."""
import hashlib
import secrets
from datetime import timedelta
from urllib.parse import urlparse

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from flask import request

from .models import AuditLog, db, now

_hasher = PasswordHasher()   # argon2id with a random salt per password


# ---------- Passwords ----------
def hash_password(password):
    return _hasher.hash(password)


def check_password(password_hash, password):
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


# A dummy hash so a login for an unknown email takes the same time as a real one
# (otherwise the response time would reveal which emails have accounts).
DUMMY_HASH = _hasher.hash("not-a-real-password")


def password_problem(password):
    """Return an error message, or None if the password is acceptable."""
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if len(password) > 128:
        return "Password is too long."
    if password.lower() in {"password123", "1234567890", "qwertyuiop", "secureshop1"}:
        return "That password is too common."
    return None


# ---------- Random tokens (email confirmation) ----------
def new_token():
    """Return (token for the link, hash to store in the database)."""
    token = secrets.token_urlsafe(32)
    return token, sha256(token)


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


def token_expiry(hours=24):
    return now() + timedelta(hours=hours)


# ---------- Safe redirects ----------
def is_safe_next(target):
    """Only allow redirects to a path on THIS site (blocks open redirects like ?next=https://evil.com)."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return False
    parts = urlparse(target)
    return not parts.scheme and not parts.netloc


# ---------- Input helpers ----------
def to_int(value, low, high):
    """Turn form text into an int between low and high, or return None if it is not valid."""
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if low <= number <= high else None


def to_cents(value, low=1, high=100_000_00):
    """'12.50' -> 1250. Returns None for anything that is not a valid money amount."""
    try:
        text = str(value).strip()
        if text.count(".") > 1 or not text.replace(".", "").isdigit():
            return None
        whole, _, frac = text.partition(".")
        if len(frac) > 2:
            return None
        cents = int(whole or "0") * 100 + int((frac + "00")[:2])
    except ValueError:
        return None
    return cents if low <= cents <= high else None


# ---------- Audit log ----------
def audit(action, user_id=None):
    db.session.add(AuditLog(user_id=user_id, action=action[:200], ip=request.remote_addr))
    db.session.commit()
