import os
import hashlib
import sqlite3
import pyotp
import bcrypt
import logging
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

# --- CONFIGURATION & LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class BankingSystem:
    def __init__(self, db_name="secure_vault.db"):
        self.db_name = db_name
        self._init_db()
        # In production, this key must be stored in an environment variable or HSM
        self.master_key = self._load_or_generate_key()
        self.cipher = Fernet(self.master_key)

    def _init_db(self):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            # Users table with security fields
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL,
                mfa_secret TEXT NOT NULL,
                encrypted_balance BLOB NOT NULL,
                account_status TEXT DEFAULT 'ACTIVE',
                failed_attempts INTEGER DEFAULT 0,
                last_login_attempt TIMESTAMP
            )''')
            # Audit trail for tracking threats
            cursor.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                user_id INTEGER,
                timestamp TIMESTAMP,
                details TEXT
            )''')
            conn.commit()

    def _load_or_generate_key(self):
        if not os.path.exists("secret.key"):
            key = Fernet.generate_key()
            with open("secret.key", "wb") as key_file:
                key_file.write(key)
        return open("secret.key", "rb").read()

    # --- PROTECTION MECHANISM: PASSWORD HASHING (BCRYPT) ---
    def hash_password(self, password):
        # Adaptive hashing: salt + work factor
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

    # --- PROTECTION MECHANISM: DATA ENCRYPTION (AES-256) ---
    def encrypt_data(self, data):
        return self.cipher.encrypt(str(data).encode('utf-8'))

    def decrypt_data(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data).decode('utf-8')

    # --- CORE FEATURE: SECURE USER REGISTRATION ---
    def register_user(self, username, password, initial_deposit):
        # SECURITY CHECK: Parameterized queries to prevent SQL Injection
        hashed_pw = self.hash_password(password)
        mfa_secret = pyotp.random_base32()
        encrypted_bal = self.encrypt_data(initial_deposit)

        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute('''INSERT INTO users (username, password_hash, mfa_secret, encrypted_balance) 
                                VALUES (?, ?, ?, ?)''', (username, hashed_pw, mfa_secret, encrypted_bal))
                conn.commit()
            print(f"[+] User {username} registered successfully.")
            print(f"[!] Save your MFA Secret Key: {mfa_secret}")
        except sqlite3.IntegrityError:
            print("[-] Error: Username already exists.")

    # --- CORE FEATURE: SECURE MULTI-FACTOR LOGIN ---
    def login(self, username, password, mfa_token):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash, mfa_secret, failed_attempts, last_login_attempt FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if not user:
                print("[-] Login Failed: Invalid Credentials.")
                return False

            user_id, stored_hash, mfa_secret, failed, last_attempt = user

            # PROTECTION: Brute Force Lockout Check (15 min lockout after 3 attempts)
            if failed >= 3:
                last_dt = datetime.strptime(last_attempt, '%Y-%m-%d %H:%M:%S.%f')
                if datetime.now() < last_dt + timedelta(minutes=15):
                    print("[-] Account locked. Try again in 15 minutes.")
                    return False

            # CHECK 1: Password Verification
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                # CHECK 2: MFA Verification
                totp = pyotp.TOTP(mfa_secret)
                if totp.verify(mfa_token):
                    # SUCCESS: Reset failed attempts
                    cursor.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user_id,))
                    conn.commit()
                    print(f"[+] Login Successful. Welcome, {username}!")
                    self._log_event("LOGIN_SUCCESS", user_id, "User authenticated via MFA.")
                    return True
                else:
                    print("[-] Login Failed: Invalid MFA Token.")
                    self._log_event("MFA_FAILURE", user_id, "Failed MFA attempt.")
            else:
                # TRACK: Increment failed attempts
                new_failed = failed + 1
                cursor.execute("UPDATE users SET failed_attempts = ?, last_login_attempt = ? WHERE id = ?", (new_failed, datetime.now(), user_id))
                conn.commit()
                print("[-] Login Failed: Invalid Credentials.")
                self._log_event("CREDENTIAL_FAILURE", user_id, f"Incorrect password attempt. Total failed: {new_failed}")
                
            return False

    def get_balance(self, username):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT encrypted_balance FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            if result:
                # Decrypting for the authenticated user session
                return self.decrypt_data(result[0])
        return None

    def _log_event(self, event_type, user_id, details):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO audit_logs (event_type, user_id, timestamp, details) VALUES (?, ?, ?, ?)",
                           (event_type, user_id, datetime.now(), details))
            conn.commit()

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    system = BankingSystem()
    
    print("--- BANKING SECURITY SYSTEM MODULE ---")
    # Simulation: 1. Registration
    # system.register_user("john_doe", "P@ssword123", 5000.0)

    # Simulation: 2. Login Attempt
    uname = input("Username: ")
    pword = input("Password: ")
    token = input("Enter 6-digit MFA Code from App: ")

    if system.login(uname, pword, token):
        balance = system.get_balance(uname)
        print(f"[*] Secure Account Balance: ${balance}")
