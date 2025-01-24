import tkinter as tk
from tkinter import messagebox
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from os import urandom
import base64

    # Funkcje szyfrowania
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_text(text: str, password: str) -> (str, str, str):
    salt = urandom(16)
    key = generate_key(password, salt)
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    encrypted_text = encryptor.update(padded_data) + encryptor.finalize()

    return (
        base64.b64encode(encrypted_text).decode(),
        base64.b64encode(salt).decode(),
        base64.b64encode(iv).decode()
    )

    # Funkcje deszyfrowania
def decrypt_text(encrypted_text: str, password: str, salt: str, iv: str) -> str:

    encrypted_text = base64.b64decode(encrypted_text)
    salt = base64.b64decode(salt)
    iv = base64.b64decode(iv)

    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_text) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

    # Funkcje bazy danych
def create_database():
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    # Tworzenie tabeli users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        salt TEXT NOT NULL,
        iv TEXT NOT NULL
    )
    """)

    # Dodanie użytkownika z zaszyfrowanym hasłem
    password, salt, iv = encrypt_text("1234", "securepassword")
    cursor.execute("INSERT INTO users (username, password, salt, iv) VALUES (?, ?, ?, ?)", 
                   ("admin", password, salt, iv))
    connection.commit()
    connection.close()

def insecure_login(username, password):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    # Pobieranie danych użytkownika
    query = f"SELECT * FROM users WHERE username = '{username}'"
    print("Zapytanie SQL:", query)
    cursor.execute(query)
    result = cursor.fetchone()
    connection.close()

    if result:
        stored_password, salt, iv = result[2], result[3], result[4]
        try:
            decrypted_password = decrypt_text(stored_password, "securepassword", salt, iv)
            if decrypted_password == password:
                return f"Zalogowano jako {result[1]}"
        except Exception as e:
            print("Błąd odszyfrowania:", e)
    return "Nieprawidłowa nazwa użytkownika lub hasło."

def secure_login(username, password):
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    # Zabezpieczone zapytanie
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    connection.close()

    if result:
        stored_password, salt, iv = result[2], result[3], result[4]
        try:
    # Klucz szyfrowania generowany ze stałego hasła
            decrypted_password = decrypt_text(stored_password, "securepassword", salt, iv)
            if decrypted_password == password:
                return f"Zalogowano jako {result[1]}"
        except Exception as e:
            print("Błąd odszyfrowania:", e)
            return "Nieprawidłowe dane logowania."
    return "Nieprawidłowa nazwa użytkownika lub hasło."

    # Interfejs graficzny
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL Injection + Encryption Demo")

        self.username_label = tk.Label(root, text="Nazwa użytkownika:")
        self.username_label.pack()

        self.username_entry = tk.Entry(root, width=30)
        self.username_entry.pack()

        self.password_label = tk.Label(root, text="Hasło:")
        self.password_label.pack()

        self.password_entry = tk.Entry(root, width=30, show="*")
        self.password_entry.pack()

        self.insecure_button = tk.Button(root, text="Niezabezpieczone logowanie", command=self.insecure_login)
        self.insecure_button.pack()

        self.secure_button = tk.Button(root, text="Zabezpieczone logowanie", command=self.secure_login)
        self.secure_button.pack()

        self.result_label = tk.Label(root, text="Wynik:")
        self.result_label.pack()

        self.result_text = tk.Text(root, height=5, width=40, state="disabled")
        self.result_text.pack()

    def insecure_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Błąd", "Wprowadź nazwę użytkownika i hasło!")
            return

        result = insecure_login(username, password)
        self.display_result(result)

    def secure_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Błąd", "Wprowadź nazwę użytkownika i hasło!")
            return

        result = secure_login(username, password)
        self.display_result(result)

    def display_result(self, result):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, result)
        self.result_text.config(state="disabled")

if __name__ == "__main__":
    create_database()
    root = tk.Tk()
    app = App(root)
    root.mainloop()
