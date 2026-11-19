"""Blue 3 - Newsletter + coupons, checkout with store credit, order confirmation and history."""
import secrets

from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from .cart import cart_lines
from .models import (Coupon, CouponRedemption, NewsletterSignup, Order, OrderItem, Product,
                     User, db, now)
from .security import audit

bp = Blueprint("shop", __name__)


class CheckoutError(Exception):
    pass


# ---------------- Newsletter ----------------
@bp.route("/newsletter", methods=["GET", "POST"])
@login_required
def newsletter():
    # SECURITY: signup is tied to a confirmed ACCOUNT, one coupon per account,
    # so nobody can farm coupons by typing many fake email addresses.
    signup = NewsletterSignup.query.filter_by(user_id=current_user.id).first()
    if request.method == "POST" and signup is None:
        code = "NEWS-" + secrets.token_hex(4).upper()          # random, not guessable
        coupon = Coupon(code=code, percent_off=10, max_uses=1, owner_id=current_user.id)
        signup = NewsletterSignup(user_id=current_user.id, coupon_code=code)
        db.session.add_all([coupon, signup])
        try:
            db.session.commit()      # unique user_id: two quick clicks still give one coupon
            audit("newsletter signup", current_user.id)
            flash("You're subscribed! Here is your 10% coupon.", "success")
        except IntegrityError:
            db.session.rollback()
            signup = NewsletterSignup.query.filter_by(user_id=current_user.id).first()
    return render_template("newsletter.html", signup=signup)


# ---------------- Coupons ----------------
def check_coupon(code, user_id):
    """Return (coupon, None) if the coupon may be used, else (None, error message)."""
    coupon = Coupon.query.filter_by(code=code.strip().upper()).first() if code else None
    if coupon is None or not coupon.is_active:
        return None, "That coupon code is not valid."
    if coupon.expires_at and coupon.expires_at < now():
        return None, "That coupon has expired."
    if coupon.uses >= coupon.max_uses:
        return None, "That coupon has been used up."
    if coupon.owner_id and coupon.owner_id != user_id:
        return None, "That coupon code is not valid."
    if CouponRedemption.query.filter_by(coupon_id=coupon.id, user_id=user_id).first():
        return None, "You have already used that coupon."
    return coupon, None


@bp.route("/checkout/coupon", methods=["POST"])
@login_required
def apply_coupon():
    coupon, error = check_coupon(request.form.get("code", "")[:30], current_user.id)
    if error:
        flash(error, "error")
    else:
        session["coupon"] = coupon.code     # only ONE coupon per order: a new one replaces the old
        flash(f"Coupon {coupon.code} applied: {coupon.percent_off}% off.", "success")
    return redirect(url_for("shop.checkout"))


@bp.route("/checkout/coupon/remove", methods=["POST"])
@login_required
def remove_coupon():
    session.pop("coupon", None)
    return redirect(url_for("shop.checkout"))


# ---------------- Checkout ----------------
@bp.route("/checkout", methods=["GET"])
@login_required
def checkout():
    lines, subtotal = cart_lines()
    if not lines:
        flash("Your cart is empty.", "error")
        return redirect(url_for("cart.view"))
    coupon, error = check_coupon(session.get("coupon"), current_user.id) if session.get("coupon") else (None, None)
    if error:
        session.pop("coupon", None)
        flash(error, "error")
    discount = subtotal * coupon.percent_off // 100 if coupon else 0
    return render_template("checkout.html", lines=lines, subtotal=subtotal, coupon=coupon,
                           discount=discount, total=subtotal - discount)


@bp.route("/checkout", methods=["POST"])
@login_required
def place_order():
    """Everything happens in ONE database transaction: either all of it succeeds or nothing does."""
    lines, subtotal = cart_lines()       # SECURITY: prices recalculated from the database
    try:
        if not lines:
            raise CheckoutError("Your cart is empty.")
        coupon = None
        if session.get("coupon"):
            coupon, error = check_coupon(session["coupon"], current_user.id)
            if error:
                session.pop("coupon", None)
                raise CheckoutError(error)
        discount = subtotal * coupon.percent_off // 100 if coupon else 0
        total = subtotal - discount
        if total < 0:
            raise CheckoutError("Invalid order total.")

        # SECURITY (race condition): check AND take the credit in ONE statement.
        # If 20 requests arrive at the same moment, only those the credit can pay for succeed.
        result = db.session.execute(
            update(User).where(User.id == current_user.id, User.store_credit >= total)
            .values(store_credit=User.store_credit - total))
        if result.rowcount != 1:
            raise CheckoutError("You don't have enough store credit for this order.")

        # Same idea for stock: never sell more than we have.
        for product, qty, _ in lines:
            result = db.session.execute(
                update(Product).where(Product.id == product.id, Product.is_active.is_(True),
                                      Product.stock >= qty)
                .values(stock=Product.stock - qty))
            if result.rowcount != 1:
                raise CheckoutError(f"Sorry, there is not enough stock of {product.name}.")

        order = Order(user_id=current_user.id, subtotal=subtotal, discount=discount, total=total,
                      coupon_code=coupon.code if coupon else None)
        db.session.add(order)
        db.session.flush()      # gives the order its id

        for product, qty, _ in lines:
            db.session.add(OrderItem(order_id=order.id, product_id=product.id, name=product.name,
                                     quantity=qty, unit_price=product.price))

        if coupon:
            # Count the use only if it is still under the limit (atomic again).
            result = db.session.execute(
                update(Coupon).where(Coupon.id == coupon.id, Coupon.is_active.is_(True),
                                     Coupon.uses < Coupon.max_uses)
                .values(uses=Coupon.uses + 1))
            if result.rowcount != 1:
                raise CheckoutError("That coupon has been used up.")
            # The database's unique rule stops the same user using it twice.
            db.session.add(CouponRedemption(coupon_id=coupon.id, user_id=current_user.id,
                                            order_id=order.id))
        db.session.commit()

    except CheckoutError as e:
        db.session.rollback()
        flash(str(e), "error")
        return redirect(url_for("cart.view"))
    except IntegrityError:
        db.session.rollback()
        session.pop("coupon", None)
        flash("That coupon has already been used.", "error")
        return redirect(url_for("cart.view"))

    session.pop("cart", None)
    session.pop("coupon", None)
    audit(f"order {order.id} placed, total {total} cents", current_user.id)
    flash("Thank you! Your order is confirmed.", "success")
    return redirect(url_for("shop.order_detail", order_id=order.id))


# ---------------- Orders ----------------
@bp.route("/orders/<int:order_id>")
@login_required
def order_detail(order_id):
    # SECURITY (IDOR): look the order up by id AND owner. Someone else's order -> 404.
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()
    if order is None:
        abort(404)
    return render_template("order.html", order=order)
