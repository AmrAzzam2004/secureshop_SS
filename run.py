"""Start SecureShop:  python run.py   then open http://127.0.0.1:5000"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # SECURITY: debug is always OFF. The debugger lets anyone run Python code on the server.
    app.run(host="127.0.0.1", port=5000, debug=False)
