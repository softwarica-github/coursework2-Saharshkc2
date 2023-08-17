import os
import shutil
import sqlite3
import tkinter as tk
from tkinter import filedialog, messagebox, Listbox, Scrollbar, Text
from cryptography.fernet import Fernet, InvalidToken


DATABASE_FILE = 'vault.db'
SECRET_KEY = b'your_generated_fernet_key_here'
session = {'username': None, 'authenticated': False}

def initialize_database():
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')

def get_user_key(username):
    return SECRET_KEY

# Generate a new Fernet key and update the SECRET_KEY variable
def generate_key():
    return Fernet.generate_key()

SECRET_KEY = generate_key()
session = {'username': None, 'authenticated': False}

def encrypt_file(file_path, key):
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        data = file.read()

    encrypted_data = fernet.encrypt(data)

    with open(file_path + '.encrypted', 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(encrypted_file_path, key):
    fernet = Fernet(key)

    with open(encrypted_file_path, 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    return decrypted_data

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

def hash_password(password):
    # For simplicity, this function just returns the password as-is (no hashing).
    # In a real-world application, you should use a secure password hashing mechanism.
    return password

def register(username, password):
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row:
            messagebox.showerror("Error", f"User '{username}' already exists. Please choose a different username.")
            return

        hashed_password = hash_password(password)
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        messagebox.showinfo("Success", f"User '{username}' registered successfully.")

        user_key = get_user_key(username)
        os.makedirs(username, exist_ok=True)
        with open(os.path.join(username, 'vault.key'), 'wb') as key_file:
            key_file.write(user_key)

def upload_file(username):
    filename = filedialog.askopenfilename()
    if filename:
        try:
            user_key = get_user_key(username)
            encrypt_file(filename, user_key)
            shutil.move(filename, os.path.join(username, os.path.basename(filename)))
            messagebox.showinfo("Success", "File uploaded successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Error occurred while uploading: {e}")
    else:
        messagebox.showerror("Error", "File not found.")

def view_files(username):
    if not session['authenticated'] or session['username'] != username:
        messagebox.showerror("Error", "You are not authorized to view files in this vault.")
        return

    vault_path = username
    files = os.listdir(vault_path)
    if not files:
        messagebox.showinfo("Info", "No files found in the vault.")
    else:
        view_dialog = tk.Toplevel()
        view_dialog.title(f"{username}'s Vault")
        view_dialog.geometry("400x200")

        listbox = Listbox(view_dialog, width=40)
        listbox.pack(pady=5)

        for file_name in files:
            listbox.insert(tk.END, file_name)

        scrollbar = Scrollbar(view_dialog, command=listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        listbox.config(yscrollcommand=scrollbar.set)

        def open_file():
            selected_index = listbox.curselection()
            if selected_index:
                selected_file = listbox.get(selected_index[0])
                selected_file_path = os.path.join(vault_path, selected_file)
                show_file_content(username, selected_file_path)

        open_button = tk.Button(view_dialog, text="Open File", command=open_file)
        open_button.pack(pady=5)

def delete_vault(username):
    if not session['authenticated'] or session['username'] != username:
        messagebox.showerror("Error", "You are not authorized to delete this vault.")
        return

    response = messagebox.askyesno("Confirmation", f"Are you sure you want to delete {username}'s vault?")
    if response:
        vault_path = username
        files = os.listdir(vault_path)
        try:
            for file_name in files:
                if file_name != 'vault.key':
                    file_path = os.path.join(vault_path, file_name)
                    os.remove(file_path)
            messagebox.showinfo("Success", f"Contents of {username}'s vault (except vault.key) have been deleted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Error occurred while deleting the vault contents: {e}")

def login(username, password):
    if authenticate_user(username, password):
        session['username'] = username
        session['authenticated'] = True
        messagebox.showinfo("Success", f"Welcome, {username}! Login successful.")
    else:
        session['username'] = None
        session['authenticated'] = False
        messagebox.showerror("Error", "Invalid credentials. Please check your username and password.")

def read_file_content(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            return content
    except Exception as e:
        messagebox.showerror("Error", f"Error occurred while reading the file: {e}")
        return None

def show_file_content(username, file_path):
    content = read_file_content(file_path)
    if content is not None:
        content_window = tk.Toplevel()
        content_window.title(f"{username}'s File Content")
        content_window.geometry("400x400")

        text_widget = Text(content_window, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True)
        text_widget.insert(tk.END, content)
        text_widget.config(state=tk.DISABLED)

class FileVaultGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Vault")
        self.geometry("400x300")
        initialize_database()
        self.create_widgets()

    def create_widgets(self):
        self.welcome_label = tk.Label(self, text="Welcome to the File Vault GUI")
        self.welcome_label.pack(pady=10)

        self.command_label = tk.Label(self, text="Choose a command:")
        self.command_label.pack(pady=5)

        self.register_button = tk.Button(self, text="Register a new user", command=self.show_register_dialog)
        self.register_button.pack(pady=5)

        self.login_button = tk.Button(self, text="Login with an existing user", command=self.show_login_dialog)
        self.login_button.pack(pady=5)

        self.quit_button = tk.Button(self, text="Quit", command=self.quit)
        self.quit_button.pack(pady=5)

    def show_register_dialog(self):
        register_dialog = tk.Toplevel(self)
        register_dialog.title("Register")
        register_dialog.geometry("300x150")

        username_label = tk.Label(register_dialog, text="Username:")
        username_label.pack(pady=5)
        username_entry = tk.Entry(register_dialog)
        username_entry.pack(pady=5)

        password_label = tk.Label(register_dialog, text="Password:")
        password_label.pack(pady=5)
        password_entry = tk.Entry(register_dialog, show="*")
        password_entry.pack(pady=5)

        register_button = tk.Button(register_dialog, text="Register", command=lambda: self.register_user(register_dialog, username_entry.get(), password_entry.get()))
        register_button.pack(pady=5)

    def show_login_dialog(self):
        login_dialog = tk.Toplevel(self)
        login_dialog.title("Login")
        login_dialog.geometry("300x150")

        username_label = tk.Label(login_dialog, text="Username:")
        username_label.pack(pady=5)
        username_entry = tk.Entry(login_dialog)
        username_entry.pack(pady=5)

        password_label = tk.Label(login_dialog, text="Password:")
        password_label.pack(pady=5)
        password_entry = tk.Entry(login_dialog, show="*")
        password_entry.pack(pady=5)

        login_button = tk.Button(login_dialog, text="Login", command=lambda: self.login_user(login_dialog, username_entry.get(), password_entry.get()))
        login_button.pack(pady=5)

    def register_user(self, dialog, username, password):
        if username and password:
            register(username, password)
            dialog.destroy()
        else:
            messagebox.showerror("Error", "Username and password cannot be empty.")

    def login_user(self, dialog, username, password):
        if username and password:
            login(username, password)
            if session['authenticated']:
                self.show_user_actions(username)
                dialog.destroy()
        else:
            messagebox.showerror("Error", "Username and password cannot be empty.")

    def show_user_actions(self, username):
        actions_dialog = tk.Toplevel(self)
        actions_dialog.title(f"{username}'s Vault")
        actions_dialog.geometry("400x200")

        upload_button = tk.Button(actions_dialog, text="Upload File", command=lambda: upload_file(username))
        upload_button.pack(pady=5)

        view_button = tk.Button(actions_dialog, text="View Files", command=lambda: view_files(username))
        view_button.pack(pady=5)

        delete_button = tk.Button(actions_dialog, text="Delete Vault", command=lambda: delete_vault(username))
        delete_button.pack(pady=5)

def main():
    app = FileVaultGUI()
    app.mainloop()

if __name__ == '__main__':
    main()
