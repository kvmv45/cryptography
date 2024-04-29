import bcrypt # type: ignore

# Function to hash password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password, salt

# Example usage
password = input("Enter the password: ")
hashed_password, salt = hash_password(password)
print(hashed_password)
print(salt)