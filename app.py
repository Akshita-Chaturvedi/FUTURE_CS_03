# app.py
import os
import sqlite3
import hashlib
import io
from flask import Flask, request, render_template, send_file, redirect, url_for, flash, jsonify
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Load .env for development
load_dotenv()

# Configuration
APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-change-me")  # flask secret key
MASTER_PASSPHRASE = os.environ.get("MASTER_PASSPHRASE", None)
SALT = os.environ.get("KEY_SALT", None)  # optional
STORAGE_DIR = os.environ.get("STORAGE_DIR", "storage")
DB_PATH = os.environ.get("DB_PATH", "metadata.db")
KEY_ITER = int(os.environ.get("KEY_ITER", "200000"))  # PBKDF2 iterations

if MASTER_PASSPHRASE is None:
    raise RuntimeError("Set MASTER_PASSPHRASE environment variable (or use keygen.py to create one).")

if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = APP_SECRET

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            stored_name TEXT,
            filesize INTEGER,
            sha256 TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.commit()
    return conn

db = get_db()

def derive_key(passphrase: bytes, salt: bytes = None, iterations: int = 200000, key_len=32):
    """Derive a 256-bit AES key from passphrase using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = b"static_salt_please_change"
    # PBKDF2 from PyCryptodome; specify hash via hmac_hash_module from Crypto.Hash import SHA256
    from Crypto.Hash import SHA256
    return PBKDF2(passphrase, salt, dkLen=key_len, count=iterations, hmac_hash_module=SHA256)

def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext

def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    if len(blob) < 28:
        raise ValueError("Invalid blob")
    nonce = blob[:12]
    tag = blob[12:28]
    ciphertext = blob[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def file_sha256(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

# derive app key once
SALT_BYTES = SALT.encode() if SALT else None
APP_KEY = derive_key(MASTER_PASSPHRASE.encode(), salt=SALT_BYTES, iterations=KEY_ITER)

@app.route("/")
def index():
    cur = db.cursor()
    cur.execute("SELECT id, filename, filesize, sha256, created_at FROM files ORDER BY created_at DESC")
    files = cur.fetchall()
    return render_template("index.html", files=files)

@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files.get("file")
    if not uploaded:
        flash("No file part", "error")
        return redirect(url_for("index"))

    filename = secure_filename(uploaded.filename)
    if filename == "":
        flash("Empty filename", "error")
        return redirect(url_for("index"))

    data = uploaded.read()
    sha = file_sha256(data)
    encrypted = encrypt_bytes(data, APP_KEY)

    stored_name = hashlib.sha256(get_random_bytes(16)).hexdigest()
    stored_path = os.path.join(STORAGE_DIR, stored_name)

    with open(stored_path, "wb") as f:
        f.write(encrypted)

    cur = db.cursor()
    cur.execute("INSERT INTO files (filename, stored_name, filesize, sha256) VALUES (?, ?, ?, ?)",
                (filename, stored_name, len(data), sha))
    db.commit()

    flash(f"Uploaded and encrypted {filename}", "success")
    return redirect(url_for("index"))

@app.route("/download/<int:file_id>", methods=["GET"])
def download(file_id):
    cur = db.cursor()
    cur.execute("SELECT filename, stored_name, sha256 FROM files WHERE id = ?", (file_id,))
    row = cur.fetchone()
    if not row:
        return "File not found", 404
    filename, stored_name, orig_sha = row
    stored_path = os.path.join(STORAGE_DIR, stored_name)
    if not os.path.exists(stored_path):
        return "Stored file missing", 500

    with open(stored_path, "rb") as f:
        blob = f.read()

    try:
        plaintext = decrypt_bytes(blob, APP_KEY)
    except Exception as e:
        return f"Decryption failed: {str(e)}", 500

    if file_sha256(plaintext) != orig_sha:
        return "Integrity check failed", 500

    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=filename
    )

@app.route("/api/files", methods=["GET"])
def api_list():
    cur = db.cursor()
    cur.execute("SELECT id, filename, filesize, sha256, created_at FROM files ORDER BY created_at DESC")
    rows = cur.fetchall()
    files = []
    for r in rows:
        files.append({
            "id": r[0],
            "filename": r[1],
            "filesize": r[2],
            "sha256": r[3],
            "created_at": r[4]
        })
    return jsonify(files)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
