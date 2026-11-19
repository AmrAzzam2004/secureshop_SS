"""Blue 1 - User account page: view/update profile, change password, view own orders."""
import secrets

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user

from .models import Order, db
from .security import audit, check_password, hash_password, password_problem

bp = Blueprint("account", __name__, url_prefix="/account")


@bp.route("/", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        # SECURITY: read ONLY the fields users may change. Extra fields such as is_admin=1
        # or store_credit=99999 in the request are simply ignored (no mass assignment).
        name = request.form.get("name", "").strip()
        address = request.form.get("address", "").strip()
        if len(name) > 80 or len(address) > 200:
            flash("Name must be under 80 characters and address under 200.", "error")
        else:
            current_user.name = name
            current_user.address = address
            db.session.commit()
            flash("Profile updated.", "success")
        return redirect(url_for("account.profile"))

    # SECURITY: only this user's own orders.
    orders = (Order.query.filter_by(user_id=current_user.id)
              .order_by(Order.created_at.desc()).all())
    return render_template("account.html", orders=orders)


@bp.route("/password", methods=["POST"])
@login_required
def change_password():
    current = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    confirm = request.form.get("confirm", "")

    # SECURITY: must know the current password (a stolen session alone is not enough).
    if not check_password(current_user.password_hash, current):
        flash("Your current password is not correct.", "error")
    elif password_problem(new):
        flash(password_problem(new), "error")
    elif new != confirm:
        flash("The two new passwords do not match.", "error")
    else:
        user = current_user._get_current_object()
        user.password_hash = hash_password(new)
        user.session_token = secrets.token_hex(32)   # log out every other device
        db.session.commit()
        session.clear()
        session.permanent = True
        login_user(user)                             # keep this device logged in
        audit("password changed", user.id)
        flash("Password changed.", "success")
    return redirect(url_for("account.profile"))
