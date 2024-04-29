import hashlib
import os
import binascii

# Function to generate a PBKDF2 hash
def generate_pbkdf2_hash(password, salt=None, iterations=100000, dklen=32, hashfunc=hashlib.sha256):
    if salt is None:
        salt = os.urandom(16)  # Generate a random 16-byte salt
    key = hashlib.pbkdf2_hmac(hashfunc().name, password.encode('utf-8'), salt, iterations, dklen)
    return key, salt

# Example usage
password = input("Enter the password: ")
hashed_key, salt = generate_pbkdf2_hash(password)
print("PBKDF2 Hash:", binascii.hexlify(hashed_key))
print("Salt:", binascii.hexlify(salt))
