#!/usr/bin/env python3
import os
from sympy import isprime
import socket

HOSTNAME = '127.0.0.1'
PORT = 65432


def setup_client_connection(n_prime, primitive_root):
    init_connection = True
    print('Entered method')
    hex_prime = hex(n_prime)
    hex_root = hex(primitive_root)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
        soc.bind((HOSTNAME, PORT))
        soc.listen()
        conn, addr = soc.accept()
        with conn:
            print('Connected by', addr)
            if init_connection:
                init_connection = False
                conn.sendall(bytes(hex_prime, 'utf-8'))
                conn.sendall(bytes(hex_root, 'utf-8'))
            while True:
                data = conn.recv(1024)
                print(data)
                if not data:
                    break
                conn.sendall(data)


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
                binary_n = bin(n_prime)
                primitive_root = find_primitive_root(test_prime, n_prime)

                if primitive_root == -1:
                    continue
                else:
                    return n_prime, primitive_root


def init():
    n_prime, primitive_root = initial_values()
    setup_client_connection(n_prime, primitive_root)


init()

