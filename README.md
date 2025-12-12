# 🔐 Secure File Sharing System  
### Cyber Security Internship – Task 3  
Built using **Python, Flask, AES Encryption (PyCryptodome)**

---

## 📌 Overview

This project is a **Secure File Sharing System** that allows users to safely upload and download files.  
Security is the main focus — all files are **encrypted using AES-256-GCM** before storage and **decrypted** only when downloaded.

The system demonstrates real-world secure data handling techniques used in industries like healthcare, finance, and enterprise IT.

---

## 🚀 Features

### ✔ Secure File Upload  
Files uploaded through the web UI are encrypted before saving to disk.

### ✔ AES-256-GCM Encryption  
- Ensures **confidentiality**  
- Includes **authentication tag** for integrity  
- Prevents tampering  

### ✔ Encrypted Storage  
Encrypted blobs stored in `/storage` with random filenames.

### ✔ Secure File Download  
Files are:
1. Decrypted  
2. Verified with SHA-256  
3. Returned to the user  

### ✔ Metadata Tracking  
SQLite database stores:
- Original filename  
- Random stored name  
- File size  
- SHA-256 hash (for integrity)  
- Upload timestamp  

### ✔ Integrity Testing Script  
A test script uploads → downloads → verifies SHA-256 to ensure full correctness.

---

## 🏗 Project Structure

myproject/
│
├── app.py # Flask backend server
├── test_integrity.py # Upload/download integrity verifier
├── check_db.py # Optional DB inspection script
├── .env # Secret environment variables (DO NOT COMMIT)
├── .env.example # Template for GitHub
├── .gitignore # Excluded files (env, venv, storage, etc.)
│
├── templates/
│ └── index.html # Web UI for upload/list/download
│
├── storage/ # Encrypted blobs stored here
│
├── metadata.db # SQLite metadata database
└── requirements.txt # Python dependencies


---

## 🔧 Installation & Setup

### 1️⃣ Clone the Repository
```bash
git clone <your-repo-url>
cd myproject


python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt

MASTER_PASSPHRASE=your_secure_passphrase
APP_SECRET=your_flask_secret
STORAGE_DIR=storage
DB_PATH=metadata.db
KEY_ITER=200000

python app.py

---

# Access in browser

http://127.0.0.1:5000

---

🔒 Security Architecture
AES-256-GCM Encryption

Used for:

File confidentiality

Tamper detection (authentication tag)

Key Derivation

PBKDF2-HMAC-SHA256

200k iterations

Salt (optional)

Produces strong AES key from master passphrase

Integrity Checking

SHA-256 stored in database

Compared during download

Prevents data corruption or modification

Secure Storage

Random encrypted filenames

No plaintext files stored anywhere

🧪 Integrity Test

Run this after the server is running:

python test_integrity.py "path/to/original/file.pdf"


Expected:

MATCH ✔️ Encryption/Decryption successful!

🗂 .gitignore

The repository includes a .gitignore that excludes:

.env
.venv/
storage/
__pycache__/
metadata.db

This prevents secrets and sensitive data from being pushed to GitHub.


🌟 Future Improvements

User authentication (Flask-Login)

Per-user file access control

Virus scanning integration

HTTPS using Nginx + Gunicorn

Audit logging

Role-based access control
