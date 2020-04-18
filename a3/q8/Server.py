#!/usr/bin/env python3

import sys
from math import gcd
from sympy import isprime
from random import randint
import socket
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Name: Harjee Johal
# UCID: 30000668
# CPSC 418 - Assignment 3

# Used for the socket
HOSTNAME = '127.0.4.18'
TTP_PORT = 31802
CLIENT_PORT = 31803


def flush_output(message_contents):
    print(message_contents, flush=True)


def hash_value(input_val):
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
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
                return candidate_safe_prime, test_prime


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def compute_d(e, phi_n):
    g, x, y = egcd(e, phi_n)

    return x % phi_n


def calculate_rsa_parameters():
    p, _ = find_safe_prime()
    q, _ = find_safe_prime()
    while p == q:
        q, _ = find_safe_prime()

    flush_output('Server: Server_p = %d' % p)
    flush_output('Server: Server_q = %d' % q)

    n = p * q
    phi_n = (p - 1) * (q - 1)
    flush_output('Server: Server_N = %d' % n)

    e = compute_e(phi_n)
    d = compute_d(e, phi_n)

    flush_output('Server: Server_e = %d' % e)
    flush_output('Server: Server_d = %d' % d)

    return p, q, n, e, d


def get_server_name():
    print('Server name: ')
    name_raw = sys.stdin.readline().strip()
    server_name = name_raw.encode('utf-8')

    return server_name


def get_ttp_sig(server_name, n, e):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOSTNAME, TTP_PORT))
        request_sign_bytes = bytes('REQUEST SIGN', 'utf-8')
        flush_output("Server: Sending 'REQUEST SIGN' = <%s>" % request_sign_bytes.hex())
        s.sendall(request_sign_bytes)

        name_size = len(server_name)
        name_size_bytes = name_size.to_bytes(4, byteorder='big')
        flush_output('Server: Sending len(S) <%s>' % name_size_bytes.hex())
        flush_output('Server: Sending S <%s>' % server_name.hex())

        s.sendall(name_size_bytes)
        s.sendall(server_name)

        n_bytes = n.to_bytes(128, byteorder='big')
        e_bytes = e.to_bytes(128, byteorder='big')

        flush_output('Server: Sending Server_N <%s>' % n_bytes.hex())
        s.sendall(n_bytes)

        flush_output('Server: Sending Server_e <%s>' % e_bytes.hex())
        s.sendall(e_bytes)

        ttp_n = int.from_bytes(s.recv(128), 'big')
        ttp_sig = int.from_bytes(s.recv(128), 'big')

        flush_output('Server: Receiving TTP_N = %d' % ttp_n)
        flush_output('Server: Receiving TTP_SIG = %d' % ttp_sig)

        flush_output('Server: TTP_N = %d' % ttp_n)
        flush_output('Server: TTP_sig = %d' % ttp_sig)

        return ttp_n, ttp_sig


def find_primitive_root(n, q):
    for num in range(1, n):
        if pow(num, 2, n) != 1 and pow(num, q, n) != 1:
            return num

    return -1


def find_n_and_g():
    while True:
        n, q = find_safe_prime()
        g = find_primitive_root(n, q)

        if g != -1:
            return n, g


def compute_k(n, g):
    n_bytes = n.to_bytes(64, byteorder='big')
    g_bytes = g.to_bytes(64, byteorder='big')

    hash_input = n_bytes + g_bytes
    hash_output = hash_value(hash_input)

    return int.from_bytes(hash_output, 'big')


def calculate_big_b(params_dict):
    n_prime = params_dict['n']
    primitive_root = params_dict['g']
    v = params_dict['v']
    flush_output('Server: v = %d' % v)

    b = secrets.randbelow(n_prime - 1)

    k = params_dict['k']
    summation = pow(primitive_root, b, n_prime) + k * v

    big_b = summation % n_prime

    flush_output('Server: b = %d' % b)

    flush_output('Server: B = %d' % big_b)

    return big_b, b


def decrypt_rsa(ciphertext, params_dict):
    d = params_dict['d']
    server_n = params_dict['server_n']

    return int(pow(ciphertext, d, server_n))


def compute_u(big_a, big_b, n):
    hash_input = big_a.to_bytes(64, byteorder='big') + big_b.to_bytes(64, byteorder='big')
    return int.from_bytes(hash_value(hash_input), 'big')


def compute_server_key(params_dict, big_a, big_b, b):
    n = params_dict['n']
    u = compute_u(big_a, big_b, n)
    flush_output('Server: u = %d' % u)

    u_b = u * b
    base_one = pow(big_a, b, n)
    base_two = pow(params_dict['v'], u_b, n)

    return (base_one * base_two) % n


def generate_m1(big_a, big_b, server_key):
    hash_input = big_a.to_bytes(64, byteorder='big') + big_b.to_bytes(64, byteorder='big') \
                 + server_key.to_bytes(64, byteorder='big')

    return hash_value(hash_input)


def calculate_m2(big_a, m1_server, server_key):
    hash_input = big_a.to_bytes(64, byteorder='big') + m1_server + server_key.to_bytes(64, byteorder='big')

    return hash_value(hash_input)


def generate_hmac(aes_key, file_bytes):
    h = hmac.HMAC(aes_key, hashes.SHA3_256(), backend=default_backend())
    h.update(file_bytes)
    return h.finalize()


def decrypt_ciphertext(ciphertext_bytes, server_key, filename):
    key_bytes = server_key.to_bytes(64, byteorder='big')
    aes_key = hash_value(key_bytes)
    iv = ciphertext_bytes[:16]

    flush_output('Server: iv = <%s>' % iv.hex())
    flush_output('Server: key = <%s>' % aes_key.hex())

    ciphertext = ciphertext_bytes[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(256).unpadder()
    unpadded_pt = unpadder.update(plaintext)
    unpadded_pt += unpadder.finalize()

    plaintext_content = unpadded_pt[:-32]
    provided_hmac = unpadded_pt[-32:]
    computed_hmac = generate_hmac(aes_key, plaintext_content)

    if provided_hmac != computed_hmac:
        return False

    data_to_write = bytes(plaintext_content)
    with open(filename, 'wb') as f_handle:
        f_handle.write(data_to_write)

    return True


def connect_to_client(params_dict):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
        flush_output('Server is running')
        soc.bind((HOSTNAME, CLIENT_PORT))
        soc.listen()
        while True:
            conn, addr = soc.accept()
            with conn:
                n_bytes = params_dict['n'].to_bytes(64, byteorder='big')
                g_bytes = params_dict['g'].to_bytes(64, byteorder='big')

                flush_output('Server: Sending N <%s>' % n_bytes.hex())
                flush_output('Server: Sending g <%s>' % g_bytes.hex())
                conn.sendall(n_bytes)
                conn.sendall(g_bytes)

                flag = conn.recv(1).decode('utf-8')
                if flag == 'r':
                    flush_output("Server: mode = 'r'")
                    i_size = int.from_bytes(conn.recv(4), 'big')
                    flush_output('Server: Receiving len(I) = %d' % i_size)

                    i = conn.recv(i_size).decode('utf-8')

                    flush_output("Server: I = '%s'" % i)

                    salt = conn.recv(16)
                    flush_output('Server: s = <%s>' % salt.hex())

                    v = int.from_bytes(conn.recv(64), 'big')
                    flush_output('Server: v = %d' % v)

                    params_dict.update({'v': v, 's': salt, 'i': i})

                    flush_output('Server: registration successful')

                elif flag == 'p':
                    flush_output("Server: mode = 'p'")

                    client_name_length = int.from_bytes(conn.recv(4), 'big')
                    client_name = conn.recv(client_name_length).decode('utf-8')

                    flush_output('Server: Receiving len(I) = %d' % client_name_length)
                    flush_output("Server: Receiving I = '%s'" % client_name)

                    server_name = params_dict['name']
                    name_length = len(server_name).to_bytes(4, byteorder='big')
                    server_n_bytes = params_dict['server_n'].to_bytes(128, byteorder='big')
                    e_bytes = params_dict['e'].to_bytes(128, byteorder='big')
                    sig_bytes = params_dict['ttp_sig'].to_bytes(128, byteorder='big')

                    flush_output("Server: Sending S <%s>" % server_name.hex())
                    flush_output('Server: Sending len(S) <%s>' % name_length.hex())
                    flush_output('Server: Sending Server_N <%s>' % server_n_bytes.hex())
                    flush_output('Server: Sending Server_e <%s>' % e_bytes.hex())
                    flush_output('Server: Sending TTP_SIG <%s>' % sig_bytes.hex())

                    conn.sendall(name_length)
                    conn.sendall(server_name)
                    conn.sendall(server_n_bytes)
                    conn.sendall(e_bytes)
                    conn.sendall(sig_bytes)

                    big_a_rsa = int.from_bytes(conn.recv(128), 'big')
                    big_a = decrypt_rsa(big_a_rsa, params_dict)

                    flush_output('Server: Receiving Enc(A) = %d' % big_a_rsa)

                    flush_output("Server: I = '%s'" % client_name)
                    flush_output("Server: Enc(A) = %d" % big_a_rsa)

                    if big_a % params_dict['n'] == 0:
                        flush_output('Server: Negotiation unsuccessful')
                        break

                    flush_output('Server: A = %d' % big_a)

                    salt = params_dict['s']
                    flush_output('Server: s = <%s>' % salt.hex())
                    flush_output('Server: Sending salt <%s>' % salt.hex())
                    conn.sendall(salt)

                    big_b, b = calculate_big_b(params_dict)

                    big_b_bytes = big_b.to_bytes(64, byteorder='big')
                    flush_output('Server: Sending B <%s>' % big_b_bytes.hex())
                    conn.sendall(big_b_bytes)

                    server_key = compute_server_key(params_dict, big_a, big_b, b)
                    flush_output('Server: k_server = %d' % server_key)

                    m1 = conn.recv(32)
                    flush_output('Server: Receiving M1 = <%s>' % m1.hex())

                    m1_server = generate_m1(big_a, big_b, server_key)
                    flush_output('Server: M1 = <%s>' % m1_server.hex())

                    if m1 == m1_server:

                        m2 = calculate_m2(big_a, m1_server, server_key)
                        flush_output('Server: M2 = <%s>' % m2.hex())
                        flush_output('Server: Sending M2 <%s>' % m2.hex())
                        conn.sendall(m2)

                        flush_output('Server: Negotiation successful')

                        ciphertext_size = int.from_bytes(conn.recv(4), 'big')
                        ciphertext = conn.recv(ciphertext_size)
                        if decrypt_ciphertext(ciphertext, server_key, params_dict['filename']):
                            flush_output('Server: File transferred successfully.')
                        else:
                            flush_output('Error occurred during file decryption')

                    else:
                        flush_output('Server: Negotiation unsuccessful')


def main():
    filename = sys.argv[1]
    server_name = get_server_name()
    n, g = find_n_and_g()
    k = compute_k(n, g)
    flush_output('Server: N = %d' % n)
    flush_output('Server: g = %d' % g)
    flush_output('Server: k = %d' % k)
    p, q, server_n, e, d = calculate_rsa_parameters()

    ttp_n, ttp_sig = get_ttp_sig(server_name, server_n, e)
    params_dict = dict(p=p, q=q, server_n=server_n, e=e, d=d, ttp_n=ttp_n, ttp_sig=ttp_sig, n=n, g=g, name=server_name,
                       filename=filename, k=k)

    connect_to_client(params_dict)


main()
