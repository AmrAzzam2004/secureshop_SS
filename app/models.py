"""Database tables. Money is always stored as whole cents (integers), never floats."""
import secrets
from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)   # argon2 hash, never the password
    name = db.Column(db.String(80), default="")
    address = db.Column(db.String(200), default="")
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_enabled = db.Column(db.Boolean, default=True, nullable=False)
    is_confirmed = db.Column(db.Boolean, default=False, nullable=False)
    store_credit = db.Column(db.Integer, default=0, nullable=False)   # cents

    # Email confirmation: we keep only a HASH of the token, plus an expiry time.
    confirm_token_hash = db.Column(db.String(64))
    confirm_expires = db.Column(db.DateTime)

    # Brute-force protection.
    failed_logins = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime)

    # SECURITY: a random value stored in the session. Changing it (on logout or password
    # change) makes every old copy of the session cookie useless.
    session_token = db.Column(db.String(64), default=lambda: secrets.token_hex(32), nullable=False)

    # SECURITY: the database itself refuses negative credit, even if the code has a bug.
    __table_args__ = (db.CheckConstraint("store_credit >= 0", name="credit_not_negative"),)

    # Flask-Login uses get_id() to put the user in the session.
    def get_id(self):
        return f"{self.id}:{self.session_token}"

    @property
    def is_active(self):          # disabled accounts cannot log in
        return self.is_enabled


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, default="")
    category = db.Column(db.String(50), default="General")
    price = db.Column(db.Integer, nullable=False)        # cents
    stock = db.Column(db.Integer, default=0, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    __table_args__ = (db.CheckConstraint("stock >= 0", name="stock_not_negative"),
                      db.CheckConstraint("price > 0", name="price_positive"))


class Coupon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(30), unique=True, nullable=False)
    percent_off = db.Column(db.Integer, nullable=False)   # 1..100
    max_uses = db.Column(db.Integer, default=1, nullable=False)
    uses = db.Column(db.Integer, default=0, nullable=False)
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    # Newsletter coupons belong to one user, so they cannot be shared.
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    __table_args__ = (db.CheckConstraint("uses <= max_uses", name="uses_within_limit"),
                      db.CheckConstraint("percent_off BETWEEN 1 AND 100", name="percent_range"))


class CouponRedemption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coupon_id = db.Column(db.Integer, db.ForeignKey("coupon.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"))
    # SECURITY: one user can use the same coupon only once - enforced by the database.
    __table_args__ = (db.UniqueConstraint("coupon_id", "user_id", name="one_use_per_user"),)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    subtotal = db.Column(db.Integer, nullable=False)
    discount = db.Column(db.Integer, default=0, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    coupon_code = db.Column(db.String(30))
    created_at = db.Column(db.DateTime, default=now, nullable=False)
    items = db.relationship("OrderItem", backref="order", lazy=True)


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)     # copy, so old orders keep the old name
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Integer, nullable=False)   # price at the time of the order


class NewsletterSignup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    coupon_code = db.Column(db.String(30), nullable=False)
    created_at = db.Column(db.DateTime, default=now)


class AuditLog(db.Model):
    """Security log: logins, lockouts, orders, admin actions. Never stores passwords."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    action = db.Column(db.String(200), nullable=False)
    ip = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=now)
