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
TTP_PORT = 31802
SERVER_PORT = 31803


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


def perform_registration(params_dict):
    salt = os.urandom(16)
    x = calculate_x(salt, params_dict['pw'])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOSTNAME, SERVER_PORT))
        n_prime = s.recv(64)
        n_prime = int.from_bytes(n_prime, 'big')

        primitive_root = s.recv(64)
        primitive_root = int.from_bytes(primitive_root, 'big')

        flush_output('Client: Receiving N = %d' % n_prime)
        flush_output('Client: Receiving g = %d' % primitive_root)
        v = int(pow(primitive_root, x, n_prime))

        flush_output("Client: Sending 'r' <%s>" % bytes('r', 'utf-8').hex())
        s.sendall(bytes('r', 'utf-8'))

        user = params_dict['name']
        username_size_bytes = len(user).to_bytes(4, byteorder='big')
        flush_output('Client: Sending len(Client_name) = <%s>' % username_size_bytes.hex())
        s.sendall(username_size_bytes)

        flush_output('Client: Sending Client_name = <%s>' % user.hex())
        s.sendall(user)

        v_bytes = v.to_bytes(64, 'big')
        flush_output('Client: v = %d' % v)
        flush_output('Client: Sending v <%s>' % v_bytes.hex())
        s.sendall(v_bytes)


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


def connect_to_ttp():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOSTNAME, TTP_PORT))
        request_string = bytes('REQUEST KEY', 'utf-8')
        flush_output("Client: Sending 'REQUEST KEY' = <%s>" % request_string.hex())
        s.sendall(request_string)

        ttp_n = int.from_bytes(s.recv(128), 'big')
        ttp_e = int.from_bytes(s.recv(128), 'big')
        flush_output('Client: Receiving TTP_N = %d' % ttp_n)
        flush_output('Client: Receiving TTP_e = %d' % ttp_e)

        return ttp_n, ttp_e


def main():
    filename = sys.argv[1]
    username, password = get_user_input()
    ttp_n, ttp_e = connect_to_ttp()
    params_dict = dict(name=username, pw=password, ttp_n=ttp_n, ttp_e=ttp_e)
    perform_registration(params_dict)


main()
