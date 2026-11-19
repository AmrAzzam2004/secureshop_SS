"""Creates the SecureShop app and switches on the protections that apply to every page."""
from flask import Flask, redirect, render_template, url_for
from flask_login import LoginManager
from flask_wtf.csrf import CSRFError, CSRFProtect

from config import Config
from .models import User, db

login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    db.init_app(app)
    csrf.init_app(app)          # SECURITY: every POST must carry a valid CSRF token
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to continue."

    # Each Blue Team member owns one or more of these files.
    from .auth import bp as auth_bp            # Blue 1
    from .account import bp as account_bp      # Blue 1
    from .catalogue import bp as catalogue_bp  # Blue 2
    from .cart import bp as cart_bp            # Blue 2
    from .shop import bp as shop_bp            # Blue 3
    from .admin import bp as admin_bp          # Blue 2 + Blue 3
    for bp in (auth_bp, account_bp, catalogue_bp, cart_bp, shop_bp, admin_bp):
        app.register_blueprint(bp)

    @app.route("/")
    def home():
        return redirect(url_for("catalogue.products"))

    # Show money stored in cents as $12.50
    @app.template_filter("money")
    def money(cents):
        return f"${cents / 100:,.2f}"

    # SECURITY: security headers on every response.
    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'")
        response.headers["X-Frame-Options"] = "DENY"               # no clickjacking in iframes
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"             # don't cache private pages
        return response

    # SECURITY: friendly error pages - no stack traces or SQL errors shown to users.
    def error_page(code, message):
        return render_template("error.html", code=code, message=message), code

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        return error_page(400, "Your form expired or was not sent from this site. Please try again.")

    @app.errorhandler(400)
    def bad_request(e):
        return error_page(400, "That request was not valid.")

    @app.errorhandler(403)
    def forbidden(e):
        return error_page(403, "You are not allowed to open this page.")

    @app.errorhandler(404)
    def not_found(e):
        return error_page(404, "We couldn't find that page.")

    @app.errorhandler(413)
    def too_large(e):
        return error_page(413, "That request was too large.")

    @app.errorhandler(500)
    def server_error(e):
        db.session.rollback()
        return error_page(500, "Something went wrong on our side. Please try again.")

    with app.app_context():
        db.create_all()

    return app


@login_manager.user_loader
def load_user(user_id):
    """The session holds 'id:session_token'. If the token no longer matches (the user logged
    out or changed password), the old cookie stops working."""
    try:
        uid, token = user_id.split(":", 1)
        user = db.session.get(User, int(uid))
    except (ValueError, AttributeError):
        return None
    if user and user.session_token == token and user.is_enabled:
        return user
    return None
