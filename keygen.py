import secrets
import base64
from getpass import getpass

def generate_passphrase(nbytes=32):
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).decode()

if _name_ == "_main_":
    print("# Usage: put these into .env (DO NOT commit .env to git)")
    passphrase = generate_passphrase()
    print(f"MASTER_PASSPHRASE={passphrase}")
    # optionally set a salt
    salt = generate_passphrase(8)
    print(f"KEY_SALT={salt}")
    print("APP_SECRET=change_this_flask_secret")