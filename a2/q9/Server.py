#!/usr/bin/env python3
import secrets
from sympy import isprime
import socket

HOSTNAME = '127.0.0.1'
PORT = 65432


def setup_client_connection(N_prime, primitive_root):
    init_connection = True
    print('Entered method')
    hex_prime = bin(N_prime)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
        soc.bind((HOSTNAME, PORT))
        soc.listen()
        conn, addr = soc.accept()
        with conn:
            print('Connected by', addr)
            if init_connection:
                init_connection = False
                conn.sendall(bytearray(N_prime))
                conn.sendall(bytearray(primitive_root))
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


N_prime_not_found = True
N_prime = 0
primitive_root = -1
while N_prime_not_found:
    test_prime = secrets.randbits(511)
    if not bin(test_prime)[2] == '1':
        continue
    if test_prime % 2 == 0:
        continue
    is_prime = isprime(test_prime)

    if is_prime:
        N_prime = 2 * test_prime + 1

        if isprime(N_prime):
            primitive_root = find_primitive_root(test_prime, N_prime)

            if primitive_root == -1:
                continue
            else:
                break


setup_client_connection(N_prime, primitive_root)
