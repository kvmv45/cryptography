import binascii
import scrypt # type: ignore
import os

# Function to generate a scrypt hash
def generate_scrypt_hash(password, salt=None, N=16384, r=8, p=1, maxmem=0):
    if salt is None:
        salt = os.urandom(16)  # Generate a random 16-byte salt
    key = scrypt.hash(password, salt, N=N, r=r, p=p, buflen=64)
    return key, salt

# Example usage
password = input("Enter the password: ")
hashed_key, salt = generate_scrypt_hash(password)
print("scrypt Hash:", binascii.hexlify(hashed_key))
print("Salt:", binascii.hexlify(salt))
