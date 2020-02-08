#!/usr/bin python

import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

args = sys.argv

if len(args) < 3:
    print('Not enough args provided')
    exit(1)

password = args[1]
file_name = args[2]

with open(file_name, 'r', encoding='utf-8') as f_handle:
    file_contents = f_handle.read()

# Converts the file contents to a byte array
byte_array = bytes(file_contents, 'utf-8')

# Uses SHA-1 on the file byte array to create a 20-byte hash tag
digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
digest.update(byte_array)

# Concatenate the file byte array and the SHA-1 hash tag generated
tag = digest.finalize()
extended_byte_array = byte_array + tag

# Hash the password using SHA1, and then truncates it to 16-bytes to be used in AES
digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
digest.update(bytes(password, 'utf-8'))
password_hash = digest.finalize()
password_key = password_hash[0:16]

initial_value = os.urandom(16)

cipher_mode = modes.CBC(initial_value)

# Pads B'
padder = padding.PKCS7(128).padder()
padded_data = padder.update(extended_byte_array)
padded_byte_array = padded_data + padder.finalize()

# Encrypts B' using the SHA1 password key using an AES-128-CBC cipher
cipher = Cipher(algorithms.AES(password_key), cipher_mode, backend=default_backend())
encryptor = cipher.encryptor()
cipher_text = encryptor.update(padded_byte_array) + encryptor.finalize()

with open('example_cipher', 'wb') as f_handle:
    f_handle.write(bytes(initial_value))
    f_handle.write(bytes(cipher_text))
