"""Blue 1 - Registration, email confirmation, login and logout."""
import re
import secrets
from datetime import timedelta

from flask import (Blueprint, current_app, flash, redirect, render_template, request,
                   session, url_for)
from flask_login import current_user, login_required, login_user, logout_user

from .models import User, db, now
from .security import (DUMMY_HASH, audit, check_password, hash_password, is_safe_next,
                       new_token, password_problem, sha256, token_expiry)

bp = Blueprint("auth", __name__)

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[A-Za-z]{2,}$")


def send_email(to, subject, body):
    """No real mail server in this project: the email is printed and saved to emails.log."""
    text = f"To: {to}\nSubject: {subject}\n\n{body}\n" + "-" * 40 + "\n"
    print(text)
    with open("emails.log", "a", encoding="utf-8") as f:
        f.write(text)


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        # SECURITY: validate everything on the server.
        if not EMAIL_RE.match(email) or len(email) > 255:
            flash("Please enter a valid email address.", "error")
            return render_template("register.html", email=email)
        problem = password_problem(password)
        if problem:
            flash(problem, "error")
            return render_template("register.html", email=email)
        if password != confirm:
            flash("The two passwords do not match.", "error")
            return render_template("register.html", email=email)

        existing = User.query.filter_by(email=email).first()
        if existing is None:
            token, token_hash = new_token()
            user = User(email=email, password_hash=hash_password(password),
                        confirm_token_hash=token_hash, confirm_expires=token_expiry(24))
            db.session.add(user)
            db.session.commit()
            link = url_for("auth.confirm", token=token, _external=True)
            send_email(email, "Confirm your SecureShop account",
                       f"Open this link within 24 hours to confirm your account:\n{link}")
            audit("register", user.id)
        else:
            # Tell the real owner, but show the visitor the SAME message as a new signup.
            send_email(email, "SecureShop sign-up attempt",
                       "Someone tried to register with your email. If it was you, just log in.")

        # SECURITY: identical message either way, so attackers can't find out who has an account.
        flash("Thanks! Check your email for a confirmation link.", "success")
        return redirect(url_for("auth.login"))
    return render_template("register.html", email="")


@bp.route("/confirm/<token>")
def confirm(token):
    # SECURITY: compare hashes; token must exist, not be expired, and is deleted after use.
    user = User.query.filter_by(confirm_token_hash=sha256(token)).first()
    if user is None or user.confirm_expires is None or user.confirm_expires < now():
        flash("This confirmation link is invalid or has expired.", "error")
        return redirect(url_for("auth.login"))
    user.is_confirmed = True
    user.confirm_token_hash = None      # single use
    user.confirm_expires = None
    db.session.commit()
    audit("account confirmed", user.id)
    flash("Your account is confirmed. You can log in now.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("catalogue.products"))
    next_url = request.args.get("next", "")

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        next_url = request.form.get("next", "")
        generic_error = "Invalid email or password."   # SECURITY: same message for every failure

        user = User.query.filter_by(email=email).first()
        if user is None:
            check_password(DUMMY_HASH, password)        # same timing as a real check
            flash(generic_error, "error")
            return render_template("login.html", next=next_url)

        # SECURITY: account lockout after too many failed attempts (stops brute force).
        if user.locked_until and user.locked_until > now():
            check_password(DUMMY_HASH, password)
            flash(generic_error + " Too many attempts - try again later.", "error")
            return render_template("login.html", next=next_url)

        if not check_password(user.password_hash, password):
            user.failed_logins += 1
            if user.failed_logins >= current_app.config["MAX_FAILED_LOGINS"]:
                user.locked_until = now() + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])
                user.failed_logins = 0
                db.session.commit()
                audit("account locked after failed logins", user.id)
            else:
                db.session.commit()
                audit("failed login", user.id)
            flash(generic_error, "error")
            return render_template("login.html", next=next_url)

        if not user.is_confirmed:
            flash("Please confirm your email first (check your inbox).", "error")
            return render_template("login.html", next=next_url)
        if not user.is_enabled:
            flash("This account has been disabled.", "error")
            return render_template("login.html", next=next_url)

        # Success.
        user.failed_logins = 0
        user.locked_until = None
        db.session.commit()
        session.clear()                 # SECURITY: start a brand-new session (stops session fixation)
        session.permanent = True        # use the 30-minute lifetime from config
        login_user(user)
        audit("login", user.id)
        # SECURITY: only redirect to our own pages (stops open redirect).
        return redirect(next_url if is_safe_next(next_url) else url_for("catalogue.products"))

    return render_template("login.html", next=next_url if is_safe_next(next_url) else "")


@bp.route("/logout", methods=["POST"])   # POST + CSRF token, so another site can't log you out
@login_required
def logout():
    user = current_user._get_current_object()
    user.session_token = secrets.token_hex(32)   # SECURITY: old session cookies stop working
    db.session.commit()
    audit("logout", user.id)
    logout_user()
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("catalogue.products"))
