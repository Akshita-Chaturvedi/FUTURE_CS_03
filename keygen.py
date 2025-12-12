# keygen.py
import secrets
import base64

def generate_passphrase(nbytes=32):
    """Generate a secure random passphrase."""
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).decode()

if __name__ == "__main__":
    print("# Usage: Copy these into your .env file (DO NOT commit .env to GitHub)")
    
    passphrase = generate_passphrase()
    print(f"MASTER_PASSPHRASE={passphrase}")
    
    # optional salt
    salt = generate_passphrase(8)
    print(f"KEY_SALT={salt}")
    
    print("APP_SECRET=change_this_flask_secret")
