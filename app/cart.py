"""Blue 2 - Shopping cart kept in the session.

The cart stores ONLY product ids and quantities. Prices always come from the database,
so a user can never change what they pay by editing the request.
"""
from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from .models import Product, db
from .security import to_int

bp = Blueprint("cart", __name__, url_prefix="/cart")

MAX_PER_ITEM = 10


def get_cart():
    cart = session.get("cart", {})
    return cart if isinstance(cart, dict) else {}


def cart_lines():
    """Build the cart from the database: [(product, quantity, line_total)], total."""
    lines, total = [], 0
    for pid, qty in get_cart().items():
        product = db.session.get(Product, int(pid))
        if product and product.is_active:
            lines.append((product, qty, product.price * qty))
            total += product.price * qty
    return lines, total


def _valid_product(form):
    pid = to_int(form.get("product_id"), 1, 10**9)
    product = db.session.get(Product, pid) if pid else None
    return product if product and product.is_active else None


@bp.route("/")
def view():
    lines, total = cart_lines()
    return render_template("cart.html", lines=lines, total=total)


@bp.route("/add", methods=["POST"])
def add():
    product = _valid_product(request.form)
    if product is None:
        flash("That product is not available.", "error")
        return redirect(url_for("catalogue.products"))
    cart = get_cart()
    current = cart.get(str(product.id), 0)
    # SECURITY: quantity must be a whole number from 1 to the limit (no -5, 0, 1.5, abc, 99999999999).
    qty = to_int(request.form.get("quantity", "1"), 1, MAX_PER_ITEM)
    if qty is None or current + qty > min(MAX_PER_ITEM, product.stock):
        flash(f"You can have between 1 and {min(MAX_PER_ITEM, product.stock)} of this item.", "error")
        return redirect(url_for("catalogue.product", product_id=product.id))
    cart[str(product.id)] = current + qty
    session["cart"] = cart
    flash(f"Added {product.name} to your cart.", "success")
    return redirect(url_for("cart.view"))


@bp.route("/update", methods=["POST"])
def update():
    product = _valid_product(request.form)
    cart = get_cart()
    if product is None or str(product.id) not in cart:
        flash("That item is not in your cart.", "error")
        return redirect(url_for("cart.view"))
    qty = to_int(request.form.get("quantity"), 1, MAX_PER_ITEM)
    if qty is None or qty > product.stock:
        flash(f"Quantity must be between 1 and {min(MAX_PER_ITEM, product.stock)}.", "error")
    else:
        cart[str(product.id)] = qty
        session["cart"] = cart
        flash("Cart updated.", "success")
    return redirect(url_for("cart.view"))


@bp.route("/remove", methods=["POST"])
def remove():
    cart = get_cart()
    pid = to_int(request.form.get("product_id"), 1, 10**9)
    if pid and str(pid) in cart:
        del cart[str(pid)]
        session["cart"] = cart
        flash("Item removed.", "success")
    return redirect(url_for("cart.view"))
