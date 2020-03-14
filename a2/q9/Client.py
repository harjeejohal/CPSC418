#!/usr/bin/env python3

import socket
import os
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

HOSTNAME = '127.0.4.18'
PORT = 31802


def get_user_input():
    user = input('Username:')
    print(user)
    pw = input('Password:')
    print(pw)
    print("Client: I = '%s'" % user)

    return user, pw


def calculate_key_with_hash(salt, password, n_prime, primitive_root):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(bytearray(salt))
    digest.update(bytearray(password, 'utf-8'))
    hashed_val = digest.finalize()
    hashed_int = int.from_bytes(hashed_val, 'big')

    return int(pow(primitive_root, hashed_int, n_prime))


def setup_server_connection(user, password):
    salt = os.urandom(16)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOSTNAME, PORT))
        n_prime = s.recv(1024)
        n_prime = int(n_prime, 16)

        primitive_root = s.recv(1024)
        primitive_root = int(primitive_root, 16)

        v = calculate_key_with_hash(salt, password, n_prime, primitive_root)
        hex_v = bytes(v.to_bytes(64, byteorder='big')).hex()

        print("Client: Sending 'r' <%s>" % bytes('r', 'utf-8').hex())
        s.sendall(bytes('r', 'utf-8'))

        username_size = bytes(len(user).to_bytes(4, byteorder='big')).hex()
        print('Client: Sending |I| <%s>' % username_size)
        s.sendall(bytes(username_size, 'utf-8'))

        user_hex = bytes(user, 'utf-8').hex()
        print('Client: Sending I <%s>' % user_hex)
        s.sendall(bytes(user, 'utf-8'))

        salt_bytes = bytes(salt)
        print('Client: s = <%s>' % salt_bytes.hex())
        print('Client: Sending s <%s>' % salt_bytes.hex())
        s.sendall(salt_bytes)

        print('Client: v = %d' % v)
        print('Client: Sending v <%s>' % bytes(hex_v, 'utf-8'))
        s.sendall(bytes(hex_v, 'utf-8'))

        print('Client: Registration successful')

        print('Client: N = %d' % n_prime)
        print('Client: g = %d' % primitive_root)

    return n_prime, primitive_root


def compute_big_a(n_prime, primitive_root):
    a = random.randint(0, n_prime)
    big_a = int(pow(primitive_root, a, n_prime))

    a_hex = a.to_bytes(64, byteorder='big')
    print('Client: a = %s' % a_hex.hex())

    big_a_hex = big_a.to_bytes(64, byteorder='big')
    print('Client: A = %s' % big_a_hex.hex())

    return big_a


def negotiation_with_server(big_a, username):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOSTNAME, PORT))

        print("Client: Sending 'p' <%s>" % bytes('p', 'utf-8').hex())
        s.sendall(bytes('p', 'utf-8'))

        username_size = bytes(len(username).to_bytes(4, byteorder='big')).hex()
        print('Client: Sending |I| <%s>' % username_size)
        s.sendall(bytes(username_size, 'utf-8'))

        user_hex = bytes(username, 'utf-8').hex()
        print('Client: Sending I <%s>' % user_hex)
        s.sendall(bytes(username, 'utf-8'))

        big_a = bytes(big_a.to_bytes(64, byteorder='big')).hex()
        print('Client: Sending A <%s>' % big_a)
        s.sendall(bytes(big_a, 'utf-8'))

        salt = s.recv(16).hex()
        print('Client: s = <%s>' % salt)

        big_b_raw = s.recv(64)
        big_b = int(big_b_raw, 16)
        print('Client: B = %d' % big_b)


def init():
    username, password = get_user_input()
    n_prime, primitive_root = setup_server_connection(username, password)

    big_a = compute_big_a(n_prime, primitive_root)
    negotiation_with_server(big_a, username)


init()
