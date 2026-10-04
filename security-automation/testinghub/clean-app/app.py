
# Safe sample app: should PASS
import hashlib
import hmac
import os


def hash_password(pw, salt=None):
    salt = salt or os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 600_000)


def verify(pw, salt, expected):
    return hmac.compare_digest(hash_password(pw, salt)[1], expected)


def get_db_password():
    return os.environ["DB_PASSWORD"]

echo "requests==2.34.2" > tests/clean-app/requirements.txt