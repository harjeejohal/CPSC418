#!/usr/bin/env python3
import os
from sympy import isprime
import socket
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

HOSTNAME = '127.0.0.1'  # '127.0.4.18'
PORT = 65432  # 31802


def calculate_big_b(n_prime, hex_prime, primitive_root, hex_root, v):
    b = int(random.randint(0, n_prime))

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(bytes(hex_prime, 'utf-8'))
    digest.update(bytes(hex_root, 'utf-8'))
    hashed_val = digest.finalize()

    k = int.from_bytes(hashed_val, 'big')
    summation = int(pow(primitive_root, b, n_prime)) + k*v

    big_b = summation % n_prime

    b_hex = bytes(b.to_bytes(64, byteorder='big')).hex()
    print('Server: b = %s' % b_hex)

    k_hex = bytes(k.to_bytes(32, byteorder='big')).hex()
    print('Server: k = %s' % k_hex)

    big_b_hex = bytes(big_b.to_bytes(64, byteorder='big')).hex()
    print('Server: B = %s' % big_b_hex)

    return big_b, b


def compute_u(big_a, big_b, n_prime):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(bytes(big_a.to_bytes(64, byteorder='big')))
    digest.update(bytes(big_b.to_bytes(64, byteorder='big')))
    hashed_val = digest.finalize()

    hash_num = int.from_bytes(hashed_val, 'big')
    return hash_num % n_prime


def compute_server_key(big_a, v, u, b, n_prime):
    A_v = big_a * v
    u_b = u * b
    return int(pow(A_v, u_b, n_prime))


def setup_client_connection(n_prime, primitive_root):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
        print('Server is up')
        print('Server: N = %d' % n_prime)
        print('Server: g = %d' % primitive_root)
        hex_prime = bytes(n_prime.to_bytes(64, byteorder='big')).hex()
        hex_root = bytes(primitive_root.to_bytes(64, byteorder='big')).hex()
        soc.bind((HOSTNAME, PORT))
        soc.listen()
        conn, addr = soc.accept()
        with conn:
            print('Server: Sending N <%s>' % hex_prime)
            print('Server: Sending g <%s>' % hex_root)
            conn.sendall(bytes(hex_prime, 'utf-8'))
            conn.sendall(bytes(hex_root, 'utf-8'))

            r = conn.recv(1).decode('utf-8')
            i_size = int(conn.recv(8), 16)

            i = conn.recv(i_size)
            print("Server: I = '%s'" % i.decode('utf-8'))

            salt = conn.recv(16)
            print("Server: s = <%s>" % salt.hex())

            v_raw = conn.recv(16)
            v = int(v_raw, 16)
            hex_v = bytes(v.to_bytes(64, byteorder='big')).hex()
            print('Server: v = %s' % hex_v)

            print('Server: Registration successful')

        conn, addr = soc.accept()
        with conn:
            big_b, b = calculate_big_b(n_prime, hex_prime, primitive_root, hex_root, v)
            data = conn.recv(1)
            while not data.decode('utf-8') == 'p':
                data = conn.recv(1024)

            username_size = int(conn.recv(8), 16)
            username = conn.recv(username_size).decode('utf-8')
            big_a = int(conn.recv(64), 16)

            print("Server: I = '%s'" % username)
            print("Server: A = %d" % big_a)

            print('Server: Sending s <%s>' % salt.hex())
            conn.sendall(salt)

            print('Server: Sending B <%s>' % big_b)
            big_b_bytes = bytes(big_b.to_bytes(64, byteorder='big')).hex()
            conn.sendall(bytes(big_b_bytes, 'utf-8'))

            u = compute_u(big_a, big_b, n_prime)
            hex_u = bytes(u.to_bytes(32, byteorder='big')).hex()
            print('Server: u = %s' % hex_u)

            server_key = compute_server_key(big_a, v, u, b, n_prime)

            hex_server_key = bytes(server_key.to_bytes(64, byteorder='big')).hex()
            print('Server: k_server = %s' % hex_server_key)
            conn.sendall(bytes(hex_server_key, 'utf-8'))


def verify_candidate(candidate, sophie_prime, prime):
    test_two = int((prime - 1) / 2)
    test_sophie = int((prime - 1) / sophie_prime)

    if pow(candidate, test_two, prime) == 1 or pow(candidate, test_sophie, prime) == 1:
        return -1
    else:
        return candidate


def find_primitive_root(sophie_prime, prime):
    prime_minus_one = prime - 1
    for num in range(1, prime):
        if pow(num, prime_minus_one, prime) == 1:
            root = verify_candidate(num, sophie_prime, prime)
            if root == -1:
                continue
            else:
                return root

    return -1


def initial_values():
    n_prime_not_found = True
    while n_prime_not_found:
        test_prime_hex = os.urandom(64).hex()
        test_prime_bin = bin(int(test_prime_hex, 16))[:-3]
        test_prime_bin = '0b1' + test_prime_bin[2:] + '1'
        test_prime = int(test_prime_bin, 2)
        is_prime = isprime(test_prime)

        if is_prime:
            n_prime = 2 * test_prime + 1

            if isprime(n_prime):
                primitive_root = find_primitive_root(test_prime, n_prime)

                if primitive_root == -1:
                    continue
                else:
                    return n_prime, primitive_root


def init():
    n_prime, primitive_root = initial_values()
    setup_client_connection(n_prime, primitive_root)


init()
