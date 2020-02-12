#!/usr/bin python

import sys
from datetime import timedelta, date
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# This substring exists in all of Bob's plaintext messages, so this is the substring we use to verify if our chosen
# key is correct
target_substring = b'FOXHOUND'


# This method attempts to decrypt the cipher text with the password passed in. Returns the plaintext upon success, and
# throws an exception upon an incorrect decryption
def test_key(file_content, key, iv):
    # Hash the password using SHA1, and then truncates it to 16-bytes to be used in AES decryption
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(bytes(key, 'utf-8'))
    password_hash = digest.finalize()

    # The key can only be 16 bytes (128 bits), since AES-128 only accepts keys of length 128 bits
    password_key = password_hash[:16]

    # Builds the AES decryptor using the current password
    cipher = Cipher(algorithms.AES(password_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_pt = decryptor.update(file_content) + decryptor.finalize()

    if target_substring in decrypted_pt:
        return decrypted_pt
    raise Exception('Wrong key')


args = sys.argv
if len(args) < 2:
    print('Not enough args passed in')
    exit(1)

file_name = args[1]

# Reads the ciphertext file in as bytes
with open(file_name, 'rb') as f_handle:
    file_contents = f_handle.read()

# First 16 bytes of the file are the 16-byte initial value used for CBC mode with the AES-CBC-128 cipher
initial_value = file_contents[:16]

# Since Bob's passwords are important dates in his life, and he was born in 1984, the earliest important date in his
# life would be his birthday, which could be January 1, 1984 at the earliest.
start_date = date(1984, 1, 1)

# We cannot assume which days are important to Bob, so we must check all values up to and including the current day
end_date = date.today()

# The increment that we iterate by through the days between start_date and end_date
day_delta = timedelta(days=1)

# This loop iterates through all dates starting from January 1st, 1984 to the current day. For each day, it generates
# a YYYYMMDD date string, which is used as a potential key for decrypting the ciphertext
for day in range((end_date - start_date).days):
    try:
        potential_key = (start_date + day_delta * day).strftime('%Y%m%d')
        plain_text = test_key(file_contents, potential_key, initial_value)
        print(f'The password used for encryption was: {potential_key}')
    except:
        continue

# Removes the 16-byte initial value from the plain_text
plain_text = plain_text[16:]

# Removes padding
unpadder = padding.PKCS7(128).unpadder()
unpadded_pt = unpadder.update(plain_text)
unpadded_pt += unpadder.finalize()

# The hash tag generated during the original encryption of the plaintext is 160 bits, or 20 bytes, as detailed
# in the cryptography library's documentation. Therefore, if we remove the last 20 bytes of the unpadded plaintext,
# we get the plaintext byte array with the concatenated hash tag removed
original_pt = unpadded_pt[:-20]

# Converts the plaintext byte array into a string. This string is then checked for the substring 'CODE-RED', which is
# then replaced with 'CODE-BLUE' if it exists
pt_string = bytes(original_pt).decode('utf-8')
tampered_pt = pt_string.replace('CODE-RED', 'CODE-BLUE')

# Writes the decrypted/ potentially modified plaintext to an output file specified as a command-line argument
with open('modifyFile_output.txt', 'w') as f_handle:
    f_handle.write(tampered_pt)
