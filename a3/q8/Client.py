#!/usr/bin/env python3

import sys
import socket
import os
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# Name: Harjee Johal
# UCID: 30000668
# CPSC 418 - Assignment 3

HOSTNAME = '127.0.4.18'
PORT = 31802


def flush_output(message_contents):
    print(message_contents, flush=True)


def hash_value(input_val):
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest.update(input_val)
    return digest.finalize()


def calculate_x(salt, password):
    salt_pass = salt + password
    hashed_salt_pass = hash_value(salt_pass)
    return int.from_bytes(hashed_salt_pass, 'big')


def perform_registration(username, password):
    salt = os.urandom(16)
    x = calculate_x(salt, password)
    v = 

    flush_output('Client: Client_v = %d' % v)


# This is used to get the password and username from the user during registration
def get_user_input():
    print("Username: ")
    username_raw = sys.stdin.readline().strip()
    # encode it as bytes, and record the length
    username = username_raw.encode('utf-8')

    print("Password: ")
    pw_raw = sys.stdin.readline().strip()
    # encode it as bytes, and record the length
    pw = pw_raw.encode('utf-8')

    return username, pw


def main():
    filename = sys.argv[1]
    username, password = get_user_input()
    perform_registration(username, password)


main()
