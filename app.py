from flask import Flask, request, jsonify, render_template
from encryption import encrypt, decrypt

app = Flask(__name__)


def _bad(msg: str, code: int = 400):
    return jsonify({"success": False, "error": msg}), code


def _ok(data: dict):
    return jsonify({"success": True, **data}), 200


# ── Health check ─────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/health", methods=["GET"])
def health():
    return _ok({"message": "Encryption API is running.", "version": "1.0.0"})


# ── Encrypt ──────────────────────────────────────────────────────────────────

@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    """
    POST /encrypt
    Body (JSON): { "text": "...", "passphrase": "..." }
    Returns:     { "success": true, "token": "salt:iv:ciphertext" }
    """
    body = request.get_json(silent=True)
    if not body:
        return _bad("Request body must be JSON.")

    text = body.get("text", "").strip()
    passphrase = body.get("passphrase", "").strip()

    if not text:
        return _bad("'text' is required and cannot be empty.")
    if not passphrase:
        return _bad("'passphrase' is required and cannot be empty.")
    if len(passphrase) < 8:
        return _bad("'passphrase' must be at least 8 characters.")

    try:
        token = encrypt(text, passphrase)
        return _ok({"token": token})
    except Exception as e:
        return _bad(f"Encryption error: {str(e)}", 500)


# ── Decrypt ──────────────────────────────────────────────────────────────────

@app.route("/decrypt", methods=["POST"])
def decrypt_route():
    """
    POST /decrypt
    Body (JSON): { "token": "salt:iv:ciphertext", "passphrase": "..." }
    Returns:     { "success": true, "text": "..." }
    """
    body = request.get_json(silent=True)
    if not body:
        return _bad("Request body must be JSON.")

    token = body.get("token", "").strip()
    passphrase = body.get("passphrase", "").strip()

    if not token:
        return _bad("'token' is required and cannot be empty.")
    if not passphrase:
        return _bad("'passphrase' is required and cannot be empty.")

    try:
        text = decrypt(token, passphrase)
        return _ok({"text": text})
    except ValueError as e:
        return _bad(str(e), 422)
    except Exception as e:
        return _bad(f"Decryption error: {str(e)}", 500)


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(_):
    return _bad("Endpoint not found.", 404)


@app.errorhandler(405)
def method_not_allowed(_):
    return _bad("Method not allowed.", 405)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
