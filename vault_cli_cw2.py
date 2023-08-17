import os
import shutil
import sqlite3
from cryptography.fernet import Fernet, InvalidToken

DATABASE_FILE = 'vault.db'
SECRET_KEY = b'your_secret_key_here'
session = {'username': None, 'authenticated': False}

def initialize_database():
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()
    
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)
    
    with open(file_path + '.encrypted', 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()
    
    fernet = Fernet(key)
    try:
        decrypted_data = fernet.decrypt(data)
    except InvalidToken:
        print(f"Error: Failed to decrypt the file '{os.path.basename(file_path)}'.")
        return False
    
    with open(file_path[:-10], 'wb') as file:
        file.write(decrypted_data)

    return True

def get_user_key(username):
    # Generate a unique encryption key for each user using the username and the secret key.
    return Fernet.generate_key()

def authenticate_user(username, password):
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row:
            hashed_password = row[0]
            if password == hashed_password:
                return True
    return False

def register():
    username = input("Enter a username for registration: ")
    password = input("Enter a password for registration: ")

    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row:
            print(f"Error: User '{username}' already exists. Please choose a different username.")
            return

        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        print(f"User '{username}' registered successfully.")

    user_key = get_user_key(username)
    os.makedirs(username, exist_ok=True)
    with open(os.path.join(username, 'vault.key'), 'wb') as key_file:
        key_file.write(user_key)

def upload_file(username):
    
    print(f"\nUploading file to {username}'s vault...")
    filename = input("Enter the path of the file to upload: ")
    if os.path.exists(filename):
        try:
            user_key = get_user_key(username)
            encrypt_file(filename, user_key)
            shutil.move(filename, os.path.join(username, os.path.basename(filename)))
            print("File uploaded and encrypted successfully!")
        except Exception as e:
            print(f"Error occurred while uploading: {e}")
    else:
        print("Error: File not found.")

def view_files(username):
    if not session['authenticated'] or session['username'] != username:
        print("Error: You are not authorized to view files in this vault.")
        return

    print(f"\nViewing files in {username}'s vault...")
    vault_path = username
    files = os.listdir(vault_path)
    if not files:
        print("No files found in the vault.")
    else:
        for i, file_name in enumerate(files, 1):
            print(f"{i}. {file_name}")

        while True:
            choice = input("Enter the file number to view (or 'q' to quit): ")
            if choice.lower() == 'q':
                break
            elif choice.isdigit() and 1 <= int(choice) <= len(files):
                selected_file = files[int(choice) - 1]
                selected_file_path = os.path.join(vault_path, selected_file)
                with open(selected_file_path, 'r', encoding='utf-8') as file:
                    content = file.read()

                print(f"\nContent of {selected_file}:")
                print(content)
            else:
                print("Invalid choice. Please select a valid file number or 'q' to quit.")


def delete_vault(username):
    if not session['authenticated'] or session['username'] != username:
        print("Error: You are not authorized to delete this vault.")
        return

    print(f"\nDeleting {username}'s vault contents...")
    try:
        for root, dirs, files in os.walk(username):
            for file in files:
                # Skip deleting the vault.key file
                if file != 'vault.key':
                    os.remove(os.path.join(root, file))

            for dir in dirs:
                os.rmdir(os.path.join(root, dir))

        print(f"Contents of {username}'s vault have been deleted successfully!")
    except Exception as e:
        print(f"Error occurred while deleting the vault contents: {e}")

def login():
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    if authenticate_user(username, password):
        print(f"Welcome, {username}! Login successful.")
        session['username'] = username
        session['authenticated'] = True
        while True:
            print("\nChoose an option:")
            print("1. Upload file")
            print("2. View files")
            print("3. Delete vault")
            print("4. Logout")

            option = input("Enter the option number (1, 2, 3, or 4): ")

            if option == '1':
                upload_file(username)
            elif option == '2':
                view_files(username)
            elif option == '3':
                delete_vault(username)
                break
            elif option == '4':
                print(f"Logging out. Goodbye, {username}!")
                session['username'] = None
                session['authenticated'] = False
                break
            else:
                print("Error: Invalid option. Please choose a valid option.")
    else:
        print("Error: Invalid credentials. Please check your username and password.")
        session['username'] = None
        session['authenticated'] = False

def main():
    initialize_database()

    while True:
        print("\nWelcome to the File Vault CLI")
        print("Choose a command:")
        print("1. Register a new user")
        print("2. Login with an existing user")
        print("3. Quit")

        command = input("Enter the command number (1, 2, or 3): ")

        if command == '1':
            register()
        elif command == '2':
            login()
        elif command == '3':
            print("Exiting the File Vault CLI. Goodbye!")
            break
        else:
            print("Error: Invalid command. Please choose a valid option.")

if __name__ == '__main__':
    main()
