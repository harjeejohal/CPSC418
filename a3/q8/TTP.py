#!/usr/bin/env python3

from math import gcd
from sympy import isprime
from random import randint
import socket
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# Name: Harjee Johal
# UCID: 30000668
# CPSC 418 - Assignment 3

# Used for the socket
HOSTNAME = '127.0.4.18'
PORT = 31802


def flush_output(message_contents):
    print(message_contents, flush=True)


def hash_value(input_val):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(input_val)
    return digest.finalize()


def compute_e(phi_n):
    upper_bound = phi_n - 1
    while True:
        e_candidate = randint(1, upper_bound)
        if gcd(e_candidate, phi_n) == 1:
            return e_candidate


def find_safe_prime():
    while True:
        test_prime = secrets.randbits(511)
        test_prime |= 1
        test_prime |= (1 << 510)

        if isprime(test_prime):
            candidate_safe_prime = 2 * test_prime + 1

            if isprime(candidate_safe_prime):
                return candidate_safe_prime


def find_inverse(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = find_inverse(b % a, a)

    return g, x - (b // a) * y, y


def compute_d(e, phi_n):
    g, x, y = find_inverse(e, phi_n)
    return x % phi_n


def calculate_rsa_parameters():
    p = find_safe_prime()
    q = find_safe_prime()
    while p == q:
        q = find_safe_prime()

    flush_output('TTP: TTP_p = %d' % p)
    flush_output('TTP: TTP_q = %d' % q)

    n = p * q
    phi_n = (p - 1) * (q - 1)
    flush_output('TTP: TTP_N = %d' % n)

    e = compute_e(phi_n)
    d = compute_d(e, phi_n)

    flush_output('TTP: TTP_e = %d' % e)
    flush_output('TTP: TTP_d = %d' % d)

    return p, q, n, e, d


def rsa_decrypt(message, d, n):
    return int(pow(message, d, n))


def compute_ttp_sig(n, d, name, server_pk):
    concat_val = name + server_pk
    t = hash_value(concat_val)
    t_prime = hash_value(t)

    t_int = int.from_bytes((t + t_prime), 'big')
    reduced_t_int = t_int % n

    return rsa_decrypt(reduced_t_int, d, n)


def setup_socket(p, q, n, e, d):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
        flush_output('TTP is running')
        soc.bind((HOSTNAME, PORT))
        soc.listen()
        while True:
            conn, addr = soc.accept()
            with conn:
                request_type = conn.recv(12).decode('utf-8').strip()
                if request_type == 'REQUEST SIGN':
                    name_size = int.from_bytes(conn.recv(4), 'big')
                    flush_output('TTP: Receiving len(S) = %d' % name_size)

                    name_bytes = conn.recv(name_size)
                    flush_output("TTP: Receiving S = %s" % name_bytes.decode('utf-8'))

                    server_n_bytes = conn.recv(128)
                    server_e_bytes = conn.recv(128)
                    flush_output('TTP: Receiving Server_N = %d' % int.from_bytes(server_n_bytes, 'big'))
                    flush_output('TTP: Receiving Server_e = %d' % int.from_bytes(server_e_bytes, 'big'))

                    server_pk = server_n_bytes + server_e_bytes

                    ttp_sig = compute_ttp_sig(n, d, name_bytes, server_pk)
                    flush_output('TTP: TTP_SIG = %d' % ttp_sig)

                    n_bytes = n.to_bytes(128, byteorder='big')
                    sig_bytes = ttp_sig.to_bytes(128, byteorder='big')

                    flush_output('TTP: Sending TTP_N = <%s>' % n_bytes.hex())
                    flush_output('TTP: Sending TTP_SIG = <%s>' % sig_bytes.hex())

                    conn.sendall(n_bytes + sig_bytes)

                elif request_type == 'REQUEST KEY':
                    n_bytes = n.to_bytes(128, byteorder='big')
                    e_bytes = e.to_bytes(128, byteorder='big')

                    ttp_pk = n_bytes + e_bytes
                    flush_output('TTP: Sending TTP_N = <%s>' % n_bytes.hex())
                    flush_output('TTP: Sending TTP_e = <%s>' % e_bytes.hex())
                    conn.sendall(ttp_pk)

                    conn.close()
                    soc.close()
                    break


def main():
    p, q, n, e, d = calculate_rsa_parameters()
    setup_socket(p, q, n, e, d)


main()
