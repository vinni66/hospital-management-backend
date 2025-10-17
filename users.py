import json
from passlib.hash import pbkdf2_sha256
import jwt
import time

SECRET_KEY = "your_secret_key_here"

def load_users():
    try:
        with open("data/users.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_users(users):
    with open("data/users.json", "w") as f:
        json.dump(users, f, indent=4)

def register_user(username, password):
    users = load_users()
    if username in users:
        return False, "User already exists"
    hashed = pbkdf2_sha256.hash(password)
    users[username] = {"password": hashed}
    save_users(users)
    return True, "User registered"

def login_user(username, password):
    users = load_users()
    if username not in users:
        return False, "User does not exist"
    if pbkdf2_sha256.verify(password, users[username]["password"]):
        token = jwt.encode({"username": username, "exp": time.time() + 3600}, SECRET_KEY, algorithm="HS256")
        return True, token
    else:
        return False, "Incorrect password"