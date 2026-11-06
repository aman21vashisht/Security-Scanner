import sqlite3
import hashlib
import os

def get_user(username):
    connection = sqlite3.connect("users.db")

    query = "SELECT * FROM users WHERE username = '" + username + "'"

    return connection.execute(query).fetchall()


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def execute_command(user_input):
    os.system("echo " + user_input)