"""Create sample data:  python seed.py   (deletes and recreates the database)."""
from app import create_app
from app.models import Coupon, Product, User, db
from app.security import hash_password

PRODUCTS = [
    ("Wireless Mouse", "Accessories", 1999, 25, "Quiet 2.4 GHz mouse with a 12-month battery."),
    ("Mechanical Keyboard", "Accessories", 6999, 10, "Tactile switches and a full-size layout."),
    ("USB-C Hub", "Accessories", 3499, 15, "HDMI, 3 x USB-A and SD card reader."),
    ("27-inch Monitor", "Screens", 21999, 5, "2560 x 1440 IPS panel."),
    ("Laptop Stand", "Office", 2999, 20, "Aluminium stand with adjustable height."),
    ("Noise-Cancelling Headphones", "Audio", 12999, 8, "Over-ear, 30-hour battery."),
    ("Webcam HD", "Video", 4599, 12, "1080p webcam with a privacy shutter."),
    ("Desk Lamp", "Office", 2499, 18, "LED lamp with three brightness levels."),
]

app = create_app()
with app.app_context():
    db.drop_all()
    db.create_all()
    db.session.add_all([
        User(email="admin@secureshop.local", password_hash=hash_password("Admin#Pass2026"),
             name="Shop Admin", is_admin=True, is_confirmed=True, store_credit=50000),
        User(email="user@secureshop.local", password_hash=hash_password("User#Pass2026"),
             name="Test User", is_confirmed=True, store_credit=10000),
        User(email="user2@secureshop.local", password_hash=hash_password("User2#Pass2026"),
             name="Second User", is_confirmed=True, store_credit=10000),
    ])
    for name, cat, price, stock, desc in PRODUCTS:
        db.session.add(Product(name=name, category=cat, price=price, stock=stock, description=desc))
    db.session.add(Coupon(code="WELCOME10", percent_off=10, max_uses=100))
    db.session.commit()
    print("Database ready.")
    print("  Admin: admin@secureshop.local / Admin#Pass2026")
    print("  User:  user@secureshop.local  / User#Pass2026   ($100 credit)")
    print("  User2: user2@secureshop.local / User2#Pass2026  ($100 credit, for IDOR tests)")
