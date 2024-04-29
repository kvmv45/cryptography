import binascii
import argon2 # type: ignore
import os

# Function to generate an Argon2 hash
def generate_argon2_hash(password, salt=None, time_cost=16, memory_cost=2**14, parallelism=1, hash_len=32):
    if salt is None:
        salt = os.urandom(16)  # Generate a random 16-byte salt
    argon2_hasher = argon2.PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism, hash_len=hash_len)
    hashed_password = argon2_hasher.hash(password, salt=salt)
    return hashed_password, salt

# Example usage
password = input("Enter the password: ")
hashed_password, salt = generate_argon2_hash(password)
print("Argon2 Hash:", hashed_password)
print("Salt:", binascii.hexlify(salt))
