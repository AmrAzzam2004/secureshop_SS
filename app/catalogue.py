"""Blue 2 - Product list, product detail, search and filter."""
from flask import Blueprint, abort, render_template, request

from .models import Product, db
from .security import to_cents

bp = Blueprint("catalogue", __name__)


@bp.route("/products")
def products():
    q = request.args.get("q", "").strip()[:100]           # limit length
    category = request.args.get("category", "").strip()[:50]
    max_price_text = request.args.get("max_price", "").strip()

    # SECURITY: the ORM sends q, category and max_price as PARAMETERS, never as SQL text,
    # so input like  ' OR 1=1 --  is just searched for as words (no SQL injection).
    query = Product.query.filter_by(is_active=True)
    if q:
        query = query.filter(Product.name.ilike(f"%{q}%") | Product.description.ilike(f"%{q}%"))
    if category:
        query = query.filter(Product.category == category)
    max_price = to_cents(max_price_text) if max_price_text else None
    if max_price_text and max_price is None:
        error = "Max price must be a number like 25 or 25.50."
    else:
        error = None
        if max_price:
            query = query.filter(Product.price <= max_price)

    categories = [c for (c,) in db.session.query(Product.category)
                  .filter_by(is_active=True).distinct().order_by(Product.category)]
    # The search term is shown back on the page; Jinja2 escapes it automatically (no XSS).
    return render_template("products.html", products=query.order_by(Product.name).all(),
                           q=q, category=category, max_price=max_price_text,
                           categories=categories, error=error)


@bp.route("/product/<int:product_id>")      # <int:...> means only numbers are accepted
def product(product_id):
    item = db.session.get(Product, product_id)
    if item is None or not item.is_active:
        abort(404)
    return render_template("product.html", product=item)
