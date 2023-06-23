import getpass
import hashlib
import getpass
import random


# Password Management Functions

def generate_password(length=12):
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=~"
    password = ""
    for _ in range(length):
        password += random.choice(characters)
    return password

def hash_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

def verify_password(password, hashed_password):
    return hashed_password == hash_password(password)



# Main Program

def main():
    print("=== Security Automation Tool: Password Management ===")
    print("1. Generate a password")
    print("2. Hash a password")
    print("3. Verify a password")
    choice = input("Enter your choice (1-3): ")

    if choice == "1":
        length = int(input("Enter the desired length of the password: "))
        password = generate_password(length)
        print("Generated Password:", password)


    if choice == "2":
        password = getpass.getpass("Enter the password to hash: ")
        hashed_password = hash_password(password)
        print("Hashed Password:", hashed_password)

    elif choice == "3":
        password = getpass.getpass("Enter the password to verify: ")
        hashed_password = input("Enter the hashed password: ")
        if verify_password(password, hashed_password):
            print("Password is verified.")
        else:
            print("Password verification failed.")



    else:
        print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
