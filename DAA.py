import tkinter as tk
from tkinter import messagebox
import sqlite3
import secrets
import string
from cryptography.fernet import Fernet

# Generate or load encryption key
def load_key():
    try:
        with open("key.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
        return key

encryption_key = load_key()
cipher = Fernet(encryption_key)

# Database setup
def init_db():
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT,
            username TEXT,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Function to add password
def save_password():
    website = website_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    if not website or not username or not password:
        messagebox.showerror("Error", "All fields are required!")
        return
    
    encrypted_password = cipher.encrypt(password.encode())
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)",
                   (website, username, encrypted_password))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "Password Saved!")
    website_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

# Function to retrieve password
def get_password():
    website = website_entry.get()
    if not website:
        messagebox.showerror("Error", "Enter a website to search!")
        return
    
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username, password FROM passwords WHERE website = ?", (website,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        username, encrypted_password = result
        decrypted_password = cipher.decrypt(encrypted_password).decode()
        messagebox.showinfo("Result", f"Username: {username}\nPassword: {decrypted_password}")
    else:
        messagebox.showerror("Error", "No password found for this website!")

# Function to generate a strong password
def generate_password():
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(chars) for _ in range(12))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

# GUI Setup
root = tk.Tk()
root.title("Password Manager")
root.geometry("400x400")

# Labels and Entry Fields
tk.Label(root, text="Website").pack()
website_entry = tk.Entry(root)
website_entry.pack()

tk.Label(root, text="Username").pack()
username_entry = tk.Entry(root)
username_entry.pack()

tk.Label(root, text="Password").pack()
password_entry = tk.Entry(root, show="*")
password_entry.pack()

# Buttons
tk.Button(root, text="Save Password", command=save_password).pack()
tk.Button(root, text="Get Password", command=get_password).pack()
tk.Button(root, text="Generate Password", command=generate_password).pack()

root.mainloop()