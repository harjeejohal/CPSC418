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


# This is from when I thought that the order of the print statements mattered. I used this to ensure that the
# statements were flushed immediately
def flush_output(message_contents):
    print(message_contents, flush=True)


# This method is used to apply a hash function to a provided byte array. By default, this method uses SHA3-256.
# However, there is an optional flag to provide your own hash function, which is used during signature validation
def hash_value(input_val, hash_to_use=hashes.SHA3_256()):
    digest = hashes.Hash(hash_to_use, backend=default_backend())
    digest.update(input_val)
    return digest.finalize()


# Calculates x = H(s || p), where s is a 16-byte salt, p is the user's password, and H is the SHA3-256 hash function
def calculate_x(s):
    salt_pass = s + password
    hashed_salt_pass = hash_value(salt_pass)
    return int.from_bytes(hashed_salt_pass, 'big')


# Performs an RSA encryption of a message, (message)^e (mod N). Since this method to encrypt using both the server's
# RSA public key and the TTP's public key, the (n, e) being used must be passed into the method.
def rsa_encrypt(message, e, n):
    return pow(message, e, n)


# This method computes (t || t'), where t = H(Server_name || Server_n || Server_e), where H is the SHA3-512 hash
# function, and t' = H(t). The value (t || t') is interpreted as an integer, t_int, and used to compute t_int % TTP_N.
# Then, this value is compared to the encryption of TTP_SIG under RSA's public key.
# Since TTP_SIG = (t_int % TTP_N)^TTP_d (mod TTP_N), then that means that when we encrypt this, we should get
# (t_int % TTP_N)^(TTP_e * TTP_d) (mod TTP_N) = t_int % TTP_N. Therefore, the value we compute should equal the
# encryption of TTP_SIG under TTP's public key. If it does, then the server's signature is verified to be legitimate.
# Otherwise, we return False, indicating that the signature was invalid.
def check_signature(server_name, server_n, server_e, ttp_sig):
    server_n_bytes = server_n.to_bytes(128, byteorder='big')
    server_e_bytes = server_e.to_bytes(128, byteorder='big')

    hash_input = bytes(server_name, 'utf-8') + server_n_bytes + server_e_bytes
    t = hash_value(hash_input, hashes.SHA3_512())
    t_prime = hash_value(t, hashes.SHA3_512())

    t_int = int.from_bytes(t + t_prime, 'big')
    reduced_t_int = t_int % ttp_n

    sig_comparison = rsa_encrypt(ttp_sig, ttp_e, ttp_n)

    return sig_comparison == reduced_t_int


# Calculates k_client = (B - kv)^(a + ux) (mod N)
def calculate_client_key(big_a, big_b, x, v, a, n_prime, primitive_root):
    a_bytes = big_a.to_bytes(64, byteorder='big')
    b_bytes = big_b.to_bytes(64, byteorder='big')
    all_bytes = a_bytes + b_bytes

    hashed_val = hash_value(all_bytes)
    hash_num = int.from_bytes(hashed_val, 'big')
    u = hash_num % n_prime

    flush_output('Client: u = %d' % u)

    n_bytes = n_prime.to_bytes(64, 'big')
    root_bytes = primitive_root.to_bytes(64, 'big')
    all_bytes = n_bytes + root_bytes

    k_hash = hash_value(all_bytes)
    k = int.from_bytes(k_hash, 'big')

    flush_output('Client: k = %d' % k)

    base = big_b - k * v
    exponent = u * x + a

    return pow(base, exponent, n_prime)


# This is used to get the password and username from the user during registration
def get_user_input():
    print("Username: ")
    username_raw = sys.stdin.readline().strip()
    # encode it as bytes, and record the length
    name = username_raw.encode('utf-8')

    print("Password: ")
    pw_raw = sys.stdin.readline().strip()
    # encode it as bytes, and record the length
    pw = pw_raw.encode('utf-8')

    return name, pw


# Computes A = g^a (mod N)
def compute_big_a(n, g):
    a = secrets.randbelow(n - 1)
    big_a = pow(g, a, n)

    flush_output('Client: a = %d' % a)
    flush_output('Client: A = %d' % big_a)

    return a, big_a


# Computes M1 = H(A || B || k_client), where H is the SHA3-256 hash function
def generate_m1(big_a, big_b, client_key):
    a_bytes = big_a.to_bytes(64, byteorder='big')
    b_bytes = big_b.to_bytes(64, byteorder='big')
    client_key_bytes = client_key.to_bytes(64, byteorder='big')
    all_bytes = a_bytes + b_bytes + client_key_bytes

    return hash_value(all_bytes)


# Computes M2 = H(A || M1 || k_client), where H is the SHA3-256 hash function
def calculate_m2(big_a, m1, client_key):
    big_a_bytes = big_a.to_bytes(64, byteorder='big')
    key_bytes = client_key.to_bytes(64, byteorder='big')
    all_bytes = big_a_bytes + m1 + key_bytes

    return hash_value(all_bytes)


# Encrypts a file under AES-256. The key used for AES is the SHA3-256 hash of k_client. The mode used is CBC. We also
# compute the SHA3-256 hash of the file contents and append them to the end of the file's byte content as a tag.
# This version of the file contents is then padded and encrypted under AES-256. Then, it is send to the server.
def encrypt_file(client_key):
    key_bytes = client_key.to_bytes(64, byteorder='big')
    aes_key = hash_value(key_bytes)
    iv = os.urandom(16)
    with open(filename, 'rb') as f_handle:
        file_bytes = f_handle.read()

    computed_hmac = hash_value(file_bytes)

    file_hmac = file_bytes + computed_hmac

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_hmac)
    final_padded_data = padded_data + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    return iv + encryptor.update(final_padded_data) + encryptor.finalize()


# This method is used to connect to the TTP. Upon connection, the client receives (TTP_N || TTP_e)
def connect_to_ttp():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOSTNAME, TTP_PORT))
        request_string = bytes('REQUEST KEY', 'utf-8')
        s.sendall(request_string)

        n_ttp = int.from_bytes(s.recv(128), 'big')
        e_ttp = int.from_bytes(s.recv(128), 'big')
        flush_output('Client: TTP_N = %d' % n_ttp)
        flush_output('Client: TTP_e = %d' % e_ttp)

        return n_ttp, e_ttp


# This method performs user registration with the server. The client sends (len(I), I, s, v)
def perform_registration(salt, x):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOSTNAME, SERVER_PORT))
        n_prime = s.recv(64)
        n_prime = int.from_bytes(n_prime, 'big')

        primitive_root = s.recv(64)
        primitive_root = int.from_bytes(primitive_root, 'big')

        flush_output('Client: Server_N = %d' % n_prime)
        flush_output('Client: Server_g = %d' % primitive_root)
        v = pow(primitive_root, x, n_prime)

        flush_output("Client: Sending mode <%s>" % bytes('r', 'utf-8').hex())
        s.sendall(bytes('r', 'utf-8'))

        username_size_bytes = len(username).to_bytes(4, byteorder='big')
        flush_output('Client: Sending len(username) <%s>' % username_size_bytes.hex())
        s.sendall(username_size_bytes)

        flush_output('Client: Sending username <%s>' % username.hex())
        s.sendall(username)

        flush_output('Client: Sending salt <%s>' % salt.hex())
        s.sendall(salt)

        v_bytes = v.to_bytes(64, byteorder='big')
        flush_output('Client: v = %d' % v)
        flush_output('Client: Sending v <%s>' % v_bytes.hex())
        s.sendall(v_bytes)

        del salt
        del x

        flush_output('Client: Registration successful.')


# This method performs the protocol for deriving a shared key with the server. Upon connection, the client sends the
# server (len(I), I). Then, the server sends back (len(S), S, Server_N, Server_e, TTP_SIG). The client uses this
# info to verify whether the server's signature is legitimate or not. If it is, then the client generates and then
# encrypts A under the server's public RSA key, and then sends Enc(A) to the server. The server sends the client
# (s, B) where, s is the salt that the client sent to the server during registration. The client uses this information
# to generate k_client, after which it generates M1 and M2 to confirm that k_server = k_client. Once this is confirmed,
# the client encrypts a file, Enc(file), and sends the server (len(Enc) || Enc(file))
def perform_protocol():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOSTNAME, SERVER_PORT))

        n = int.from_bytes(s.recv(64), byteorder='big')
        g = int.from_bytes(s.recv(64), byteorder='big')

        flush_output('Client: Receiving N = %d' % n)
        flush_output('Client: Receiving g = %d' % g)

        flush_output('Client: N = %d' % n)
        flush_output('Client: g = %d' % g)

        flush_output('Client: Sending I')
        flush_output("Client: Sending mode <%s>" % bytes('p', 'utf-8').hex())
        s.sendall(bytes('p', 'utf-8'))

        username_size_bytes = len(username).to_bytes(4, byteorder='big')
        flush_output('Client: Sending len(username) <%s>' % username_size_bytes.hex())
        s.sendall(username_size_bytes)

        flush_output('Client: Sending username <%s>' % username.hex())
        s.sendall(username)

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

        flush_output('Client: len(S) = %d' % server_name_len)
        flush_output("Client: S = '%s'" % server_name)
        flush_output('Client: Server_N = %d' % server_n)
        flush_output('Client: Server_e = %d' % server_e)
        flush_output('Client: TTP_SIG = %d' % ttp_sig)

        if not check_signature(server_name, server_n, server_e, ttp_sig):
            flush_output('Client: Server signature not verified')
            exit(1)
        else:
            flush_output('Client: Server signature verified')

        a, big_a = compute_big_a(n, g)
        big_a_rsa = rsa_encrypt(big_a, server_e, server_n)

        flush_output('Client: Enc(A) = %d' % big_a_rsa)

        big_a_rsa_bytes = big_a_rsa.to_bytes(128, byteorder='big')
        flush_output('Client: Sending Enc(A) <%s>' % big_a_rsa_bytes.hex())
        s.sendall(big_a_rsa_bytes)

        salt = s.recv(16)
        flush_output('Client: Receiving s = <%s>' % salt.hex())
        flush_output('Client: Client_s = <%s>' % salt.hex())

        big_b = int.from_bytes(s.recv(64), 'big')
        flush_output('Client: Receiving B = %d' % big_b)
        flush_output('Client: B = %d' % big_b)

        x = calculate_x(salt)
        v = pow(g, x, n)

        client_key = calculate_client_key(big_a, big_b, x, v, a, n, g)

        m1 = generate_m1(big_a, big_b, client_key)
        flush_output('Client: k_client = %d' % client_key)
        flush_output('Client: M1 = <%s>' % m1.hex())
        flush_output('Client: Sending M1 <%s>' % m1.hex())
        s.sendall(m1)

        m2 = calculate_m2(big_a, m1, client_key)

        flush_output('Client: M2 = <%s>' % m2.hex())
        flush_output('Client: Sending M2 <%s>' % m2.hex())

        try:
            m2_server = s.recv(32)
            if m2 == m2_server:
                flush_output('Client: Negotiation successful')

                file_ciphertext = encrypt_file(client_key)
                file_size = len(file_ciphertext)

                file_size_bytes = file_size.to_bytes(4, byteorder='big')
                flush_output('Client: Sending len(PTXT) <%s>' % file_size_bytes.hex())

                s.sendall(file_size_bytes)
                s.sendall(file_ciphertext)

                flush_output('Client: File %s sent.' % filename)

            else:
                flush_output('Client: Negotiation unsuccessful')
        except IOError:
            flush_output('Client: Negotiation unsuccessful')


# This is where the client's initial values are initialized
filename = sys.argv[1]
username, password = get_user_input()
ttp_n, ttp_e = connect_to_ttp()


def main():
    salt = os.urandom(16)
    x = calculate_x(salt)
    flush_output('Client: s = <%s>' % salt.hex())
    flush_output('Client: x = %d' % x)

    perform_registration(salt, x)
    perform_protocol()


main()
