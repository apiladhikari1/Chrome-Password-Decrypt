import os
import re
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# GLOBAL CONSTANT
CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (os.environ['USERPROFILE']))
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % (os.environ['USERPROFILE']))

def get_secret_key():
    try:
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        secret_key = secret_key[5:] 
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        messagebox.showerror("Error", "Chrome secret key cannot be found")
        return None
    
def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()  
        return decrypted_pass
    except Exception as e:
        messagebox.showerror("Error", "Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""

def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        messagebox.showerror("Error", "Chrome database cannot be found")
        return None

def decrypt_passwords():
    try:
        secret_key = get_secret_key()
        if not secret_key:
            return
        
        passwords = []
        folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$", element) is not None]
        for folder in folders:
            chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data" % (CHROME_PATH, folder))
            conn = get_db_connection(chrome_path_login_db)
            if secret_key and conn:
                cursor = conn.cursor()
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                for index, login in enumerate(cursor.fetchall()):
                    url = login[0]
                    username = login[1]
                    ciphertext = login[2]
                    if url and username and ciphertext:
                        decrypted_password = decrypt_password(ciphertext, secret_key)
                        passwords.append((index, url, username, decrypted_password))
                cursor.close()
                conn.close()
                os.remove("Loginvault.db")
        
        for password in passwords:
            tree.insert("", tk.END, values=password)
        
        messagebox.showinfo("Success", "Passwords have been decrypted and displayed successfully.")
        save_button.pack(pady=10)  # Show the save button after decryption
    except Exception as e:
        messagebox.showerror("Error", str(e))

def save_passwords():
    try:
        output_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not output_path:
            return
        
        with open(output_path, mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=',')
            csv_writer.writerow(["index", "url", "username", "password"])
            
            for row in tree.get_children():
                csv_writer.writerow(tree.item(row)['values'])
        
        messagebox.showinfo("Success", "Passwords have been saved successfully.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def create_gui():
    root = tk.Tk()
    root.title("Chrome Password Decryptor")

    frame = tk.Frame(root, padx=10, pady=10)
    frame.pack(padx=10, pady=10)

    decrypt_button = tk.Button(frame, text="Decrypt Chrome Passwords", command=decrypt_passwords)
    decrypt_button.pack(pady=10)

    global save_button
    save_button = tk.Button(frame, text="Save Passwords to CSV", command=save_passwords)
    
    global tree
    tree = ttk.Treeview(frame, columns=("index", "url", "username", "password"), show="headings")
    tree.heading("index", text="Index")
    tree.heading("url", text="URL")
    tree.heading("username", text="Username")
    tree.heading("password", text="Password")
    tree.pack(pady=10)
    
    root.mainloop()

if __name__ == '__main__':
    create_gui()
