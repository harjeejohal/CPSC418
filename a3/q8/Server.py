#!/usr/bin/env python3

import sys
from math import gcd
from sympy import isprime, mod_inverse
from random import randint
import socket
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Name: Harjee Johal
# UCID: 30000668
# CPSC 418 - Assignment 3

# Used for the socket
HOSTNAME = '127.0.4.18'
TTP_PORT = 31802
CLIENT_PORT = 31803

# This is a dictionary that contains a user's registration info. Using the username as a key, it stores the
# corresponding (s, v) tuple for that user
registered_users = dict()


# This is from when I thought that the order of the print statements mattered. I used this to ensure that the
# statements were flushed immediately
def flush_output(message_contents):
    print(message_contents, flush=True)


# This method is used to apply SHA3-256 to a provided byte array
def hash_value(input_val):
    digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
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
                return candidate_safe_prime, test_prime


# Calculates n, p, q, e, and d for RSA. Both p and q are defined to be 512-bit safe primes
def calculate_rsa_parameters():
    rsa_p, _ = find_safe_prime()
    rsa_q, _ = find_safe_prime()
    while rsa_p == rsa_q:
        rsa_q, _ = find_safe_prime()

    flush_output('Server: Server_p = %d' % rsa_p)
    flush_output('Server: Server_q = %d' % rsa_q)

    rsa_n = rsa_p * rsa_q
    phi_n = (rsa_p - 1) * (rsa_q - 1)
    flush_output('Server: Server_N = %d' % rsa_n)

    rsa_e = compute_e(phi_n)
    rsa_d = mod_inverse(rsa_e, phi_n)

    flush_output('Server: Server_e = %d' % rsa_e)
    flush_output('Server: Server_d = %d' % rsa_d)

    return rsa_p, rsa_q, rsa_n, rsa_e, rsa_d


# Reads in the server name from sys.stdin
def get_server_name():
    print('Server name: ')
    name_raw = sys.stdin.readline().strip()

    return name_raw.encode('utf-8')


# Connects to the TTP and sends it (Server_name || Server_PK), where Server_PK = (Server_N || Server_e)
# In return, it receives (TTP_N || TTP_SIG), where TTP_N is the TTP's RSA modulus, and TTP_SIG is the server's
# signature under the TTP's RSA parameters
def get_ttp_sig():
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

        server_n_bytes = server_n.to_bytes(128, byteorder='big')
        e_bytes = e.to_bytes(128, byteorder='big')

        flush_output('Server: Sending Server_N <%s>' % server_n_bytes.hex())
        s.sendall(server_n_bytes)

        flush_output('Server: Sending Server_e <%s>' % e_bytes.hex())
        s.sendall(e_bytes)

        ttp_n = int.from_bytes(s.recv(128), 'big')
        ttp_sig = int.from_bytes(s.recv(128), 'big')

        flush_output('Server: Receiving TTP_N = %d' % ttp_n)
        flush_output('Server: Receiving TTP_SIG = %d' % ttp_sig)

        flush_output('Server: TTP_N = %d' % ttp_n)
        flush_output('Server: TTP_sig = %d' % ttp_sig)

        return ttp_n, ttp_sig


# Finds a primitive root, g, for N. Since N = 2q + 1, where q is a prime, that means that
# N - 1 = 2q. Therefore, we can test if a number if a primitive root of N by checking if it
# passes the primitive root test. Namely, we check to see that for some candidate primitive root, a,
# whether a^((N - 1)/q) != 1 (mod N) for all prime factors q of N - 1. Since N - 1 = 2q, that means
# (N - 1)'s prime factors are 2 and q. Therefore, we check that a^((p - 1)/2) != 1 (mod N) and that
# a^((p - 1)/q) != 1 (mod N). If both of these statements hold, then this candidate is a primitive root
# of N.
def find_primitive_root(candidate_n, candidate_sophie):
    for num in range(1, candidate_n):
        if pow(num, 2, candidate_n) != 1 and pow(num, candidate_sophie, candidate_n) != 1:
            return num

    return -1


# Finds a 512-bit prime N, and then finds a primitive root g of N
def find_n_and_g():
    while True:
        candidate_n, candidate_sophie = find_safe_prime()
        candidate_g = find_primitive_root(candidate_n, candidate_sophie)

        if candidate_g != -1:
            return candidate_n, candidate_g


# Computes k = H(N || g), where H is the SHA3-256 hash function
def compute_k():
    n_bytes = n.to_bytes(64, byteorder='big')
    g_bytes = g.to_bytes(64, byteorder='big')

    hash_input = n_bytes + g_bytes
    hash_output = hash_value(hash_input)

    return int.from_bytes(hash_output, 'big')


# Calculates B = (g^b + kv) (mod N)
def calculate_big_b(v):
    b = secrets.randbelow(n - 1)
    summation = pow(g, b, n) + k * v

    big_b = summation % n

    flush_output('Server: b = %d' % b)

    flush_output('Server: B = %d' % big_b)

    return big_b, b


# Decrypts messages under the server's RSA parameters as (message)^Server_d (mod Server_N)
def decrypt_rsa(ciphertext):
    return int(pow(ciphertext, d, server_n))


# Computes u = H(A || B), where H is the SHA3-256 hash function
def compute_u(big_a, big_b):
    hash_input = big_a.to_bytes(64, byteorder='big') + big_b.to_bytes(64, byteorder='big')
    return int.from_bytes(hash_value(hash_input), 'big')


# Computes k_server = (AV^u)^b (mod N)
def compute_server_key(big_a, big_b, b, v):
    u = compute_u(big_a, big_b)
    flush_output('Server: u = %d' % u)

    u_b = u * b
    base_one = pow(big_a, b, n)
    base_two = pow(v, u_b, n)

    return (base_one * base_two) % n


# Computes M1 = H(A || B || K_server), where H is the SHA3-256 hash function
def generate_m1(big_a, big_b, server_key):
    hash_input = big_a.to_bytes(64, byteorder='big') + big_b.to_bytes(64, byteorder='big') \
                 + server_key.to_bytes(64, byteorder='big')

    return hash_value(hash_input)


# Computes M2 = H(A || M_1 || K_server), where H is the SHA3-256 hash function
def calculate_m2(big_a, m1_server, server_key):
    hash_input = big_a.to_bytes(64, byteorder='big') + m1_server + server_key.to_bytes(64, byteorder='big')

    return hash_value(hash_input)


# Decrypts the file sent by the client. The file is encrypted under AES-256, and uses H(K_server) as the AES key,
# where H is the SHA3-256 hash. The client sends (IV || Enc(file)), where IV is the 16-byte initial value used by
# the CBC mode during AES encryption/decryption. Lastly, the file contains a 32 byte tag at the end, which is merely
# H(file_contents), where file_contents is the decrypted file without the tag, and H is the SHA3-256 hash function.
# We compute H(file_contents) and compare it to the tag that was provided with the file given by the client. If they
# match, then we know that the contents of the file are valid/ haven't been altered.
def decrypt_ciphertext(ciphertext_bytes, server_key):
    key_bytes = server_key.to_bytes(64, byteorder='big')
    aes_key = hash_value(key_bytes)
    iv = ciphertext_bytes[:16]

    flush_output('Server: iv = <%s>' % iv.hex())
    flush_output('Server: key = <%s>' % aes_key.hex())

    ciphertext = ciphertext_bytes[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    unpadded_pt = unpadder.update(plaintext) + unpadder.finalize()

    plaintext_content = unpadded_pt[:-32]
    provided_hmac = unpadded_pt[-32:]
    computed_hmac = hash_value(plaintext_content)

    if provided_hmac != computed_hmac:
        return False

    with open(filename, 'wb') as f_handle:
        f_handle.write(plaintext_content)

    return True


# This method handles the process of client registration, the process of deriving a shared key with the client,
# and the retrieval of the encrypted file from the client. Upon successful decryption, the server prints a message
# confirming that the file was successfully transferred.
def connect_to_client(ttp_n, ttp_sig):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soc:
        flush_output('Server is running')
        soc.bind((HOSTNAME, CLIENT_PORT))
        soc.listen()
        while True:
            conn, addr = soc.accept()
            with conn:
                n_bytes = n.to_bytes(64, byteorder='big')
                g_bytes = g.to_bytes(64, byteorder='big')

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

                    registered_users[i] = (salt, v)

                    flush_output('Server: registration successful')

                elif flag == 'p':
                    flush_output("Server: mode = 'p'")

                    client_name_length = int.from_bytes(conn.recv(4), 'big')
                    client_name = conn.recv(client_name_length).decode('utf-8')

                    flush_output('Server: Receiving len(I) = %d' % client_name_length)
                    flush_output("Server: Receiving I = '%s'" % client_name)

                    name_length = len(server_name).to_bytes(4, byteorder='big')
                    server_n_bytes = server_n.to_bytes(128, byteorder='big')
                    e_bytes = e.to_bytes(128, byteorder='big')
                    sig_bytes = ttp_sig.to_bytes(128, byteorder='big')

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
                    big_a = decrypt_rsa(big_a_rsa)

                    flush_output('Server: Receiving Enc(A) = %d' % big_a_rsa)

                    flush_output("Server: I = '%s'" % client_name)
                    flush_output("Server: Enc(A) = %d" % big_a_rsa)

                    if big_a % n == 0:
                        flush_output('Server: Negotiation unsuccessful.')
                        exit(1)

                    flush_output('Server: A = %d' % big_a)

                    salt, v = registered_users[client_name]
                    flush_output('Server: s = <%s>' % salt.hex())
                    flush_output('Server: Sending salt <%s>' % salt.hex())
                    conn.sendall(salt)

                    flush_output('Server: v = %d' % v)
                    big_b, b = calculate_big_b(v)

                    big_b_bytes = big_b.to_bytes(64, byteorder='big')
                    flush_output('Server: Sending B <%s>' % big_b_bytes.hex())
                    conn.sendall(big_b_bytes)

                    server_key = compute_server_key(big_a, big_b, b, v)
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
                        if decrypt_ciphertext(ciphertext, server_key):
                            flush_output('Server: File transferred successfully.')
                        else:
                            flush_output('Server: File transferred unsuccessfully.')

                    else:
                        flush_output('Server: Negotiation unsuccessful')


# This is where the initial values are all initialized
server_name = get_server_name()
filename = sys.argv[1]
n, g = find_n_and_g()
k = compute_k()
p, q, server_n, e, d = calculate_rsa_parameters()


def main():
    flush_output('Server: N = %d' % n)
    flush_output('Server: g = %d' % g)
    flush_output('Server: k = %d' % k)

    ttp_n, ttp_sig = get_ttp_sig()

    connect_to_client(ttp_n, ttp_sig)


main()
