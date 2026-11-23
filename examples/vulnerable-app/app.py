"""Intentionally flawed source fixture. Scan this file; do not deploy it."""

import hashlib
import os
import pickle
import random
import sqlite3

API_TOKEN = "FAKE_DEMO_VALUE_NOT_A_REAL_CREDENTIAL"


def find_user(name):
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE users (name TEXT)")
    return connection.execute(f"SELECT name FROM users WHERE name = '{name}'").fetchall()


def read_upload(filename):
    return open(os.path.join("uploads", filename), encoding="utf-8")


def decode_cache(payload):
    return pickle.loads(payload)


def require_auth():
    pass


def fingerprint(data):
    return hashlib.md5(data).hexdigest()


def invitation_character(alphabet):
    return random.choice(alphabet)


def profile(name):
    return f"<p>{name}</p>"


def average(total):
    return total / 0


def loaded_config():
    return config_data
