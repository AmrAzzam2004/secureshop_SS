"""Blue 2 (products) + Blue 3 (users, coupons) - Admin panel.

SECURITY: the check below runs BEFORE every admin route, including any route added later
(deny by default). Hiding the Admin link in the menu is only for looks; this is the real check.
"""
from datetime import datetime

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy.exc import IntegrityError

from .models import AuditLog, Coupon, Order, Product, User, db
from .security import audit, to_cents, to_int

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.before_request
def admin_only():
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login", next=request.path))
    if not current_user.is_admin:
        audit(f"blocked admin access to {request.path}", current_user.id)
        abort(403)


@bp.route("/")
def dashboard():
    return render_template("admin/dashboard.html", users=User.query.count(),
                           products=Product.query.count(), orders=Order.query.count(),
                           logs=AuditLog.query.order_by(AuditLog.id.desc()).limit(30).all())


# ---------------- Users (Blue 3) ----------------
@bp.route("/users")
def users():
    return render_template("admin/users.html", users=User.query.order_by(User.id).all())


@bp.route("/users/<int:user_id>/toggle", methods=["POST"])
def toggle_user(user_id):
    user = db.session.get(User, user_id) or abort(404)
    if user.id == current_user.id:
        flash("You cannot disable your own account.", "error")
    else:
        user.is_enabled = not user.is_enabled
        db.session.commit()
        audit(f"admin {'enabled' if user.is_enabled else 'disabled'} user {user.id}", current_user.id)
        flash("User updated.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/credit", methods=["POST"])
def add_credit(user_id):
    user = db.session.get(User, user_id) or abort(404)
    amount = to_cents(request.form.get("amount", ""), 1, 1000_00)   # $0.01 .. $1000
    if amount is None:
        flash("Amount must be between 0.01 and 1000.", "error")
    else:
        user.store_credit += amount
        db.session.commit()
        audit(f"admin added {amount} cents credit to user {user.id}", current_user.id)
        flash("Credit added.", "success")
    return redirect(url_for("admin.users"))


# ---------------- Products (Blue 2) ----------------
@bp.route("/products")
def products():
    return render_template("admin/products.html", products=Product.query.order_by(Product.id).all())


@bp.route("/products/new", methods=["GET", "POST"])
@bp.route("/products/<int:product_id>/edit", methods=["GET", "POST"])
def edit_product(product_id=None):
    product = (db.session.get(Product, product_id) or abort(404)) if product_id else None
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "").strip() or "General"
        price = to_cents(request.form.get("price", ""))
        stock = to_int(request.form.get("stock", ""), 0, 100000)
        if not (1 <= len(name) <= 100) or len(description) > 2000 or len(category) > 50:
            flash("Name 1-100 characters, description up to 2000, category up to 50.", "error")
        elif price is None or stock is None:
            flash("Price must be a positive amount and stock a whole number 0-100000.", "error")
        else:
            if product is None:
                product = Product()
                db.session.add(product)
            product.name, product.description, product.category = name, description, category
            product.price, product.stock = price, stock
            product.is_active = request.form.get("is_active") == "on"
            db.session.commit()
            audit(f"admin saved product {product.id}", current_user.id)
            flash("Product saved.", "success")
            return redirect(url_for("admin.products"))
    return render_template("admin/product_form.html", product=product)


# ---------------- Coupons (Blue 3) ----------------
@bp.route("/coupons", methods=["GET", "POST"])
def coupons():
    if request.method == "POST":
        code = request.form.get("code", "").strip().upper()
        percent = to_int(request.form.get("percent_off", ""), 1, 100)
        max_uses = to_int(request.form.get("max_uses", ""), 1, 100000)
        expires_text = request.form.get("expires_at", "").strip()
        try:
            expires = datetime.strptime(expires_text, "%Y-%m-%d") if expires_text else None
        except ValueError:
            expires = "bad"
        if not code.replace("-", "").isalnum() or not (3 <= len(code) <= 30):
            flash("Code must be 3-30 letters, numbers or dashes.", "error")
        elif percent is None or max_uses is None or expires == "bad":
            flash("Percent 1-100, max uses 1-100000, date as YYYY-MM-DD.", "error")
        else:
            db.session.add(Coupon(code=code, percent_off=percent, max_uses=max_uses, expires_at=expires))
            try:
                db.session.commit()
                audit(f"admin created coupon {code}", current_user.id)
                flash("Coupon created.", "success")
            except IntegrityError:
                db.session.rollback()
                flash("A coupon with that code already exists.", "error")
        return redirect(url_for("admin.coupons"))
    return render_template("admin/coupons.html", coupons=Coupon.query.order_by(Coupon.id).all())


@bp.route("/coupons/<int:coupon_id>/toggle", methods=["POST"])
def toggle_coupon(coupon_id):
    coupon = db.session.get(Coupon, coupon_id) or abort(404)
    coupon.is_active = not coupon.is_active
    db.session.commit()
    audit(f"admin {'enabled' if coupon.is_active else 'disabled'} coupon {coupon.code}", current_user.id)
    return redirect(url_for("admin.coupons"))
