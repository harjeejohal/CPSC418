#!/usr/bin/env python3

import sys
import socket
import os
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Name: Harjee Johal
# UCID: 30000668
# CPSC 418 - Assignment 3

HOSTNAME = '127.0.4.18'
TTP_PORT = 31802
SERVER_PORT = 31803


def flush_output(message_contents):
    print(message_contents, flush=True)


def hash_value(input_val, hash_to_use):
    digest = hashes.Hash(hash_to_use, backend=default_backend())
    digest.update(input_val)
    return digest.finalize()


def calculate_x(salt, password):
    salt_pass = salt + password
    hashed_salt_pass = hash_value(salt_pass, hashes.SHA3_256())
    return int.from_bytes(hashed_salt_pass, 'big')


def rsa_encrypt(message, e, n):
    return int(pow(message, e, n))


def check_signature(params_dict):
    server_name = params_dict['server_name']
    server_n_bytes = params_dict['server_n'].to_bytes(128, byteorder='big')
    server_e_bytes = params_dict['server_e'].to_bytes(128, byteorder='big')

    hash_input = bytes(server_name, 'utf-8') + server_n_bytes + server_e_bytes
    t = hash_value(hash_input, hashes.SHA512())
    t_prime = hash_value(t, hashes.SHA512())

    ttp_n = params_dict['ttp_n']
    ttp_e = params_dict['ttp_e']
    ttp_sig = params_dict['ttp_sig']

    t_int = int.from_bytes(t + t_prime, 'big')
    reduced_t_int = t_int % ttp_n

    sig_comparison = rsa_encrypt(ttp_sig, ttp_e, ttp_n)

    return sig_comparison == reduced_t_int


def calculate_client_key(big_a, big_b, x, v, a, n_prime, primitive_root):
    a_bytes = big_a.to_bytes(64, byteorder='big')
    b_bytes = big_b.to_bytes(64, byteorder='big')
    all_bytes = a_bytes + b_bytes

    hashed_val = hash_value(all_bytes, hashes.SHA3_256())
    hash_num = int.from_bytes(hashed_val, 'big')
    u = hash_num % n_prime

    flush_output('Client: u = %d' % u)

    n_bytes = n_prime.to_bytes(64, 'big')
    root_bytes = primitive_root.to_bytes(64, 'big')
    all_bytes = n_bytes + root_bytes

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(all_bytes)
    hashed_val = digest.finalize()
    k = int.from_bytes(hashed_val, 'big')

    flush_output('Client: k = %d' % k)

    base = big_b - k * v
    exponent = u * x + a

    return int(pow(base, exponent, n_prime))


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


def compute_big_a(n, g):
    a = secrets.randbelow(n - 1)
    big_a = pow(g, a, n)

    flush_output('Client: a = %d' % a)
    flush_output('Client: A = %d' % big_a)

    return a, big_a


def generate_m1(big_a, big_b, client_key):
    a_bytes = big_a.to_bytes(64, byteorder='big')
    b_bytes = big_b.to_bytes(64, byteorder='big')
    client_key_bytes = client_key.to_bytes(64, byteorder='big')
    all_bytes = a_bytes + b_bytes + client_key_bytes

    return hash_value(all_bytes, hashes.SHA3_256())


def calculate_m2(big_a, m1, client_key):
    big_a_bytes = big_a.to_bytes(64, byteorder='big')
    key_bytes = client_key.to_bytes(64, byteorder='big')
    all_bytes = big_a_bytes + m1 + key_bytes

    return hash_value(all_bytes, hashes.SHA3_256())


def generate_hmac(aes_key, file_bytes):
    h = hmac.HMAC(aes_key, hashes.SHA3_256(), backend=default_backend())
    h.update(file_bytes)
    return h.finalize()


def encrypt_file(params_dict, client_key):
    key_bytes = client_key.to_bytes(64, byteorder='big')
    aes_key = hash_value(key_bytes, hashes.SHA3_256())
    iv = os.urandom(16)
    filename = params_dict['filename']
    with open(filename, 'rb') as f_handle:
        file_bytes = f_handle.read()

    computed_hmac = generate_hmac(aes_key, file_bytes)

    file_hmac = file_bytes + computed_hmac

    padder = padding.PKCS7(256).padder()
    padded_data = padder.update(file_hmac)
    final_padded_data = padded_data + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    return iv + encryptor.update(final_padded_data) + encryptor.finalize()


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

        flush_output("Client: Sending 'r' = <%s>" % bytes('r', 'utf-8').hex())
        s.sendall(bytes('r', 'utf-8'))

        user = params_dict['name']
        username_size_bytes = len(user).to_bytes(4, byteorder='big')
        flush_output('Client: Sending len(I) = <%s>' % username_size_bytes.hex())
        s.sendall(username_size_bytes)

        flush_output('Client: Sending I = <%s>' % user.hex())
        s.sendall(user)

        flush_output('Client: Sending s = <%s>' % salt.hex())
        s.sendall(salt)

        v_bytes = v.to_bytes(64, byteorder='big')
        flush_output('Client: v = %d' % v)
        flush_output('Client: Sending v = <%s>' % v_bytes.hex())
        s.sendall(v_bytes)

        server_name_len = int.from_bytes(s.recv(4), 'big')
        server_name = s.recv(server_name_len).decode('utf-8')
        server_n = int.from_bytes(s.recv(128), 'big')
        server_e = int.from_bytes(s.recv(128), 'big')
        ttp_sig = int.from_bytes(s.recv(128), 'big')

        flush_output('Client: Receiving len(S) = %d' % server_name_len)
        flush_output('Client: Receiving S = %s' % server_name)
        flush_output('Client: Receiving Server_N = %d' % server_n)
        flush_output('Client: Receiving Server_e = %d' % server_e)
        flush_output('Client: Receiving TTP_SIG = %d' % ttp_sig)

        params_dict.update(dict(server_name=server_name, server_n=server_n, server_e=server_e, ttp_sig=ttp_sig))
        if not check_signature(params_dict):
            flush_output('Client: Signature mismatch')
            exit(1)


def perform_protocol(params_dict):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOSTNAME, SERVER_PORT))

        n = int.from_bytes(s.recv(64), byteorder='big')
        g = int.from_bytes(s.recv(64), byteorder='big')

        flush_output('Client: Receiving N = %d' % n)
        flush_output('Client: Receiving g = %d' % g)

        a, big_a = compute_big_a(n, g)
        big_a_rsa = rsa_encrypt(big_a, params_dict['server_e'], params_dict['server_n'])

        flush_output('Client: Enc(A) = %d' % big_a_rsa)

        flush_output("Client: Sending 'p' = <%s>" % bytes('p', 'utf-8').hex())
        s.sendall(bytes('p', 'utf-8'))

        username = params_dict['name']
        username_size_bytes = len(username).to_bytes(4, byteorder='big')
        flush_output('Client: Sending |I| = <%s>' % username_size_bytes.hex())
        s.sendall(username_size_bytes)

        flush_output('Client: Sending I = <%s>' % username.hex())
        s.sendall(username)

        big_a_rsa_bytes = big_a_rsa.to_bytes(128, byteorder='big')
        flush_output('Client: Sending Enc(A) = <%s>' % big_a_rsa_bytes.hex())
        s.sendall(big_a_rsa_bytes)

        salt = s.recv(16)
        flush_output('Client: Receiving s = <%s>' % salt.hex())

        big_b = int.from_bytes(s.recv(64), 'big')
        flush_output('Client: Receiving B = %d' % big_b)

        x = calculate_x(salt, params_dict['pw'])
        v = int(pow(g, x, n))

        client_key = calculate_client_key(big_a, big_b, x, v, a, n, g)

        m1 = generate_m1(big_a, big_b, client_key)
        flush_output('Client: k_client = %d' % client_key)
        flush_output('Client: Sending M1 = <%s>' % m1.hex())
        s.sendall(m1)

        m2 = calculate_m2(big_a, m1, client_key)
        flush_output('Client: Sending M2 = <%s>' % m2.hex())

        try:
            m2_server = s.recv(32)
            if m2 == m2_server:
                flush_output('Client: Negotiation successful')

                file_ciphertext = encrypt_file(params_dict, client_key)
                file_size = len(file_ciphertext)

                file_size_bytes = file_size.to_bytes(4, byteorder='big')
                s.sendall(file_size_bytes)
                s.sendall(file_ciphertext)

            else:
                flush_output('Client: Negotiation unsuccessful')
        except IOError:
            flush_output('Client: Negotiation unsuccessful')


def main():
    filename = sys.argv[1]
    username, password = get_user_input()
    ttp_n, ttp_e = connect_to_ttp()
    params_dict = dict(name=username, pw=password, ttp_n=ttp_n, ttp_e=ttp_e, filename=filename)
    perform_registration(params_dict)
    perform_protocol(params_dict)


main()
