# Slash_Task_1
# Text Encryption API — Flask

AES-256-CBC encryption/decryption over a simple REST API.  
Every encryption call produces a unique output thanks to a random salt + IV.

## Stack

- **Flask** — web framework
- **cryptography** — AES-256-CBC + PBKDF2 key derivation (Python stdlib-backed)

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Server starts at `http://localhost:5000`.

---

## Endpoints

### `GET /`
Health check.

**Response**
```json
{ "success": true, "message": "Encryption API is running.", "version": "1.0.0" }
```

---

### `POST /encrypt`
Encrypt a text string.

**Request body**
```json
{
  "text": "Hello, world!",
  "passphrase": "my-secret-key"
}
```

**Response**
```json
{
  "success": true,
  "token": "abc123...:def456...:ghi789..."
}
```

The token is `base64(salt):base64(iv):base64(ciphertext)`.  
Identical inputs produce different tokens every call.

---

### `POST /decrypt`
Decrypt a token produced by `/encrypt`.

**Request body**
```json
{
  "token": "abc123...:def456...:ghi789...",
  "passphrase": "my-secret-key"
}
```

**Response**
```json
{
  "success": true,
  "text": "Hello, world!"
}
```

**Error (wrong key)**
```json
{
  "success": false,
  "error": "Decryption failed — wrong passphrase or corrupted data."
}
```

---

## cURL Examples

```bash
# Encrypt
curl -s -X POST http://localhost:5000/encrypt \
  -H "Content-Type: application/json" \
  -d '{"text":"Hello, world!","passphrase":"my-secret-key"}' | python -m json.tool

# Decrypt (paste token from above)
curl -s -X POST http://localhost:5000/decrypt \
  -H "Content-Type: application/json" \
  -d '{"token":"<paste-token-here>","passphrase":"my-secret-key"}' | python -m json.tool
```

---

## Security Details

| Property | Value |
|---|---|
| Algorithm | AES-256-CBC |
| Key derivation | PBKDF2-HMAC-SHA256 |
| KDF iterations | 100,000 |
| Salt | 16 bytes, random per call |
| IV | 16 bytes, random per call |
| Padding | PKCS7 |
| Token format | `base64url(salt):base64url(iv):base64url(ciphertext)` |

Minimum passphrase length: **8 characters** (enforced by the API).
