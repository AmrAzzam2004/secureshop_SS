"""Automatic checks that the main attacks FAIL against SecureShop.   Run:  python -m pytest -q"""
import re

import pytest

from app import create_app
from app.models import Coupon, Order, Product, User, db
from app.security import hash_password
from config import Config


class TestConfig(Config):
    SQLALCHEMY_DATABASE_URI = "sqlite://"     # in-memory database for tests
    SECRET_KEY = "test-secret"


@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.session.add_all([
            User(email="a@test.com", password_hash=hash_password("Password-A1"), is_confirmed=True, store_credit=5000),
            User(email="b@test.com", password_hash=hash_password("Password-B1"), is_confirmed=True, store_credit=5000),
            User(email="admin@test.com", password_hash=hash_password("Password-Ad"), is_confirmed=True, is_admin=True),
            Product(name="Mouse", price=1000, stock=5, description="mouse"),
            Product(name="Secret", price=500, stock=5, is_active=False),
            Coupon(code="ONCE", percent_off=50, max_uses=1),
        ])
        db.session.commit()
    return app      # the app context is closed so each request gets a fresh one, like a real server


@pytest.fixture
def client(app):
    return app.test_client()


def token(client, path="/login"):
    """Read the CSRF token from a page's form, like a real browser would."""
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).get_data(as_text=True)).group(1)


def login(client, email, password):
    return client.post("/login", data={"email": email, "password": password, "csrf_token": token(client)})


def test_sql_injection_in_search_returns_nothing_extra(client):
    page = client.get("/products?q=' OR 1=1 --").get_data(as_text=True)
    assert "Secret" not in page and "No products match" in page


def test_xss_in_search_is_escaped(client):
    page = client.get("/products?q=<script>alert(1)</script>").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page


def test_post_without_csrf_token_is_rejected(client):
    login(client, "a@test.com", "Password-A1")
    assert client.post("/checkout").status_code == 400


def test_sql_injection_login_bypass_fails(client):
    page = login(client, "a@test.com' --", "x").get_data(as_text=True)
    assert "Invalid email or password" in page


def test_lockout_after_five_failures(client):
    for _ in range(5):
        login(client, "a@test.com", "wrong-password")
    page = login(client, "a@test.com", "Password-A1").get_data(as_text=True)
    assert "Too many attempts" in page


def test_open_redirect_blocked(client):
    r = client.post("/login", data={"email": "a@test.com", "password": "Password-A1",
                                    "next": "https://evil.com", "csrf_token": token(client)})
    assert "evil.com" not in r.headers["Location"]


def test_normal_user_cannot_open_admin(client):
    login(client, "a@test.com", "Password-A1")
    assert client.get("/admin/users").status_code == 403


def test_idor_other_users_order_is_404(app, client):
    with app.app_context():
        b = User.query.filter_by(email="b@test.com").first()
        db.session.add(Order(user_id=b.id, subtotal=100, total=100))
        db.session.commit()
        order_id = Order.query.first().id
    login(client, "a@test.com", "Password-A1")
    assert client.get(f"/orders/{order_id}").status_code == 404


def test_mass_assignment_ignored(app, client):
    login(client, "a@test.com", "Password-A1")
    client.post("/account/", data={"name": "A", "is_admin": "1", "store_credit": "999999",
                                   "csrf_token": token(client, "/account/")})
    with app.app_context():
        a = User.query.filter_by(email="a@test.com").first()
        assert not a.is_admin and a.store_credit == 5000


@pytest.mark.parametrize("qty", ["-5", "0", "1.5", "abc", "99999999999"])
def test_bad_quantities_rejected(client, qty):
    client.post("/cart/add", data={"product_id": "1", "quantity": qty, "csrf_token": token(client)})
    assert "Mouse" not in client.get("/cart/").get_data(as_text=True)


def test_coupon_cannot_be_used_twice(client):
    login(client, "a@test.com", "Password-A1")
    for _ in range(2):
        t = token(client, "/products")
        client.post("/cart/add", data={"product_id": "1", "quantity": "1", "csrf_token": t})
        client.post("/checkout/coupon", data={"code": "ONCE", "csrf_token": t})
        client.post("/checkout", data={"csrf_token": t})
    page = client.post("/checkout/coupon", data={"code": "ONCE", "csrf_token": token(client, "/products")},
                       follow_redirects=True).get_data(as_text=True)
    assert "used up" in page or "already used" in page


def test_cannot_spend_more_credit_than_you_have(app, client):
    login(client, "a@test.com", "Password-A1")       # has $50.00; mouse is $10.00, 5 in stock
    t = token(client, "/products")
    for _ in range(6):
        client.post("/cart/add", data={"product_id": "1", "quantity": "1", "csrf_token": t})
        client.post("/checkout", data={"csrf_token": t})
    with app.app_context():
        a = User.query.filter_by(email="a@test.com").first()
        assert a.store_credit >= 0 and db.session.get(Product, 1).stock >= 0


def test_security_headers_present(client):
    r = client.get("/products")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


def test_old_session_cookie_dead_after_logout(client):
    login(client, "a@test.com", "Password-A1")
    stolen = client.get_cookie("session").value
    client.post("/logout", data={"csrf_token": token(client, "/products")})
    client.set_cookie("session", stolen)
    assert client.get("/account/").status_code == 302      # sent to login, not logged in
