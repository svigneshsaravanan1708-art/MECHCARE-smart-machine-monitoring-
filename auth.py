
import csv
import os
import hashlib
import secrets
import hmac

USER_FILE = "users.csv"

ROLES = ["Admin", "Technician", "Viewer"]

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        300000
    ).hex()

    return hashed, salt


def initialize_users():
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                "username",
                "password_hash",
                "salt",
                "role"
            ])


def get_users():
    initialize_users()

    with open(USER_FILE, "r", newline="") as file:
        return list(csv.DictReader(file))


def create_user(username, password, role):
    initialize_users()

    username = username.strip()

    if not username or not password:
        return False, "Username and password are required."

    if role not in ROLES:
        return False, "Invalid role."

    if len(password) < 8:
        return False, "Password must have at least 8 characters."

    users = get_users()

    if any(u["username"].lower() == username.lower()
           for u in users):
        return False, "Username already exists."

    hashed, salt = hash_password(password)

    with open(USER_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([username, hashed, salt, role])

    return True, "User created successfully."


def verify_login(username, password):
    users = get_users()

    for user in users:
        if user["username"].lower() == username.strip().lower():

            hashed, _ = hash_password(
                password,
                user["salt"]
            )

            if hmac.compare_digest(
                hashed,
                user["password_hash"]
            ):
                return {
                    "username": user["username"],
                    "role": user["role"]
                }

    return None


def has_permission(role, action):
    permissions = {
        "Admin": {
            "view",
            "add",
            "edit",
            "delete",
            "manage_users",
            "reports"
        },

        "Technician": {
            "view",
            "add",
            "edit",
            "reports"
        },

        "Viewer": {
            "view",
            "reports"
        }
    }

    return action in permissions.get(role, set())
