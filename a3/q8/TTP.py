#!/usr/bin/env python3

from math import gcd
from sympy import isprime
from sympy.core.numbers import mod_inverse
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


# This is from when I thought that the order of the print statements mattered. I used this to ensure that the
# statements were flushed immediately
def flush_output(message_contents):
    print(message_contents, flush=True)


# Used to hash (Server_name || Server_PK) and (t) when computing TTP_SIG
def hash_value(input_val):
    digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    digest.update(input_val)
    return digest.finalize()


# Computes a value for e such that 1 <= e < phi(n), and gcd(e, phi(n)) = 1
def compute_e(phi_n):
    upper_bound = phi_n - 1
    while True:
        e_candidate = randint(1, upper_bound)
        if gcd(e_candidate, phi_n) == 1:
            return e_candidate


# Finds 512-bit primes of the form p = 2q + 1, where q is also a prime
def find_safe_prime():
    while True:
        test_prime = secrets.randbits(511)
        test_prime |= 1
        test_prime |= (1 << 510)

        if isprime(test_prime):
            candidate_safe_prime = 2 * test_prime + 1

            if isprime(candidate_safe_prime):
                return candidate_safe_prime


# Calculates n, p, q, e, and d for RSA. Both p and q are defined to be 512-bit safe primes
def calculate_rsa_parameters():
    rsa_p = find_safe_prime()
    rsa_q = find_safe_prime()
    while rsa_p == rsa_q:
        rsa_q = find_safe_prime()

    flush_output('TTP: TTP_p = %d' % rsa_p)
    flush_output('TTP: TTP_q = %d' % rsa_q)

    rsa_n = rsa_p * rsa_q
    phi_n = (rsa_p - 1) * (rsa_q - 1)
    flush_output('TTP: TTP_N = %d' % rsa_n)

    rsa_e = compute_e(phi_n)
    rsa_d = mod_inverse(rsa_e, phi_n)

    flush_output('TTP: TTP_e = %d' % rsa_e)
    flush_output('TTP: TTP_d = %d' % rsa_d)

    return rsa_p, rsa_q, rsa_n, rsa_e, rsa_d


# Decrypts messages as (message)^d % n
def rsa_decrypt(message):
    return pow(message, d, n)


# Computes the TTP signature for the server. First, we compute the SHA3-512 hash of (Server_name || Server_PK) to get t,
# and then we determine the SHA3-512 hash of t to get t'. We then interpret (t || t') as an integer, t_int, and return
# the RSA decryption of (t_int % n) under the TTP's d and n
def compute_ttp_sig(name, server_pk):
    concat_val = name + server_pk
    t = hash_value(concat_val)
    t_prime = hash_value(t)

    t_bytes = t + t_prime
    t_int = int.from_bytes(t_bytes, 'big')
    reduced_t_int = t_int % n

    return rsa_decrypt(reduced_t_int)


# This method opens up a socket that listens for connections from both the server and the client. If a request is
# received from the server, the TTP receives (len(S) || S || Server_PK), where Server_PK = (Server_N || Server_e). These
# values are then used to compute TTP_SIG for this server. The TTP then sends back (TTP_SIG || TTP_N) to the server.
#
# If the TTP receives a request from the client, it sends (TTP_N || TTP_e) to the client.
def setup_socket():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
        flush_output('TTP is running')
        soc.bind((HOSTNAME, PORT))
        soc.listen()
        while True:
            conn, addr = soc.accept()
            with conn:
                request_type_init = conn.recv(11).decode('utf-8')
                if request_type_init == 'REQUEST SIG':
                    request_type_last_byte = conn.recv(1).decode('utf-8')
                    request_type = request_type_init + request_type_last_byte
                else:
                    request_type = request_type_init

                flush_output("TTP: Receiving '%s'" % request_type)
                if request_type == 'REQUEST SIGN':
                    flush_output('Random print statement')
                    name_size = int.from_bytes(conn.recv(4), 'big')
                    flush_output('TTP: Receiving len(S) = %d' % name_size)

                    name_bytes = conn.recv(name_size)
                    flush_output("TTP: Receiving S = '%s'" % name_bytes.decode('utf-8'))
                    flush_output("TTP: S = '%s'" % name_bytes.decode('utf-8'))

                    server_n_bytes = conn.recv(128)
                    server_e_bytes = conn.recv(128)
                    flush_output('TTP: Receiving Server_N = %d' % int.from_bytes(server_n_bytes, 'big'))
                    flush_output('TTP: Receiving Server_e = %d' % int.from_bytes(server_e_bytes, 'big'))

                    flush_output('TTP: Server_N = %d' % int.from_bytes(server_n_bytes, 'big'))
                    flush_output('TTP: Server_e = %d' % int.from_bytes(server_e_bytes, 'big'))

                    server_pk = server_n_bytes + server_e_bytes

                    ttp_sig = compute_ttp_sig(name_bytes, server_pk)
                    flush_output('TTP: TTP_SIG = %d' % ttp_sig)

                    n_bytes = n.to_bytes(128, byteorder='big')
                    sig_bytes = ttp_sig.to_bytes(128, byteorder='big')

                    flush_output('TTP: Sending TTP_N = <%s>' % n_bytes.hex())
                    flush_output('TTP: Sending TTP_SIG = <%s>' % sig_bytes.hex())

                    conn.sendall(n_bytes)
                    conn.sendall(sig_bytes)

                elif request_type == 'REQUEST KEY':
                    n_bytes = n.to_bytes(128, byteorder='big')
                    e_bytes = e.to_bytes(128, byteorder='big')

                    ttp_pk = n_bytes + e_bytes
                    flush_output('TTP: Sending TTP_N = <%s>' % n_bytes.hex())
                    flush_output('TTP: Sending TTP_e = <%s>' % e_bytes.hex())
                    conn.sendall(ttp_pk)


# This is where the TTP's RSA parameters are initialized
p, q, n, e, d = calculate_rsa_parameters()


def main():
    setup_socket()


main()
