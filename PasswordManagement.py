from flask import Flask, render_template, request, redirect, session, url_for
from cryptography.fernet import Fernet

import sqlite3
import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'

def load_key():
    with open("secret.key", "rb") as f:
        return f.read()

fernet = Fernet(load_key())

def init_db():
    with sqlite3.connect('password_manager.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        hashed_password TEXT,
                        registration_datetime TEXT
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS credentials (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        site TEXT,
                        login_username TEXT,
                        login_password TEXT,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )''')
        conn.commit()

def encrypt_password(password):
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return fernet.decrypt(encrypted_password.encode()).decode()

def generate_salt(password: str, datetime_str: str, salt_length: int = 16) -> str:
    seed_input = password
    seed = sum(ord(char) for char in password)

    # LCG constants
    a = 1103515245
    c = 12345
    m = 2**31

    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    salt = ""

    for _ in range(salt_length):
        seed = (a * seed + c) % m
        salt += charset[seed % len(charset)]

    salt += datetime_str

    return salt

def right_rotate(n, d):
    return (n >> d) | (n << (32 - d)) & 0xFFFFFFFF

def sha256(message):
    # Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    H = [
        0x6a09e667, 0xbb67ae85,
        0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19
    ]

    # Round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # Convert to binary
    message_bytes = bytearray(message, 'utf-8')
    original_len_bits = len(message_bytes) * 8
    message_bytes.append(0x80)

    while ((len(message_bytes) * 8 + 64) % 512) != 0:
        message_bytes.append(0x00)

    message_bytes += original_len_bits.to_bytes(8, 'big')

    # Process the message in 512-bit chunks
    for i in range(0, len(message_bytes), 64):
        chunk = message_bytes[i:i + 64]
        w = [int.from_bytes(chunk[j:j + 4], 'big') for j in range(0, 64, 4)]

        for j in range(16, 64):
            s0 = right_rotate(w[j - 15], 7) ^ right_rotate(w[j - 15], 18) ^ (w[j - 15] >> 3)
            s1 = right_rotate(w[j - 2], 17) ^ right_rotate(w[j - 2], 19) ^ (w[j - 2] >> 10)
            w.append((w[j - 16] + s0 + w[j - 7] + s1) & 0xFFFFFFFF)

        a, b, c, d, e, f, g, h = H

        for j in range(64):
            S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[j] + w[j]) & 0xFFFFFFFF

            S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        H = [(x + y) & 0xFFFFFFFF for x, y in zip(H, [a, b, c, d, e, f, g, h])]

    # Produce the final hash value (big-endian hex)
    return ''.join(f'{value:08x}' for value in H)

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        registration_datetime = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        salt = generate_salt(password, registration_datetime)
        mid = len(salt) // 2
        hash_input = salt[:mid] + password + salt[mid:]
        hashed = sha256(hash_input)

        with sqlite3.connect('password_manager.db') as conn:
            c = conn.cursor()
            try:
                c.execute("INSERT INTO users (username, hashed_password, registration_datetime) VALUES (?, ?, ?)",
                          (username, hashed, registration_datetime))
                conn.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                return 'Username already exists.'

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect('password_manager.db') as conn:
            c = conn.cursor()
            c.execute("SELECT id, hashed_password, registration_datetime FROM users WHERE username = ?", (username,))
            result = c.fetchone()

            if result:
                user_id, stored_hash, datetime = result
                salt = generate_salt(password, datetime)
                mid = len(salt) // 2
                check_hash = sha256(salt[:mid] + password + salt[mid:])
                if check_hash == stored_hash:
                    session['username'] = username
                    session['user_id'] = user_id
                    return redirect(url_for('dashboard'))
        error = f'Invalid username or password.'
        return render_template('login.html', error=error)

    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    with sqlite3.connect('password_manager.db') as conn:
        c = conn.cursor()
        if request.method == 'POST':
            site = request.form['site']
            login_username = request.form['login_username']
            login_password = request.form['login_password']
            encrypted_password = encrypt_password(login_password)
            c.execute("INSERT INTO credentials (user_id, site, login_username, login_password) VALUES (?, ?, ?, ?)",
                      (user_id, site, login_username, encrypted_password))
            conn.commit()

        c.execute("SELECT id, site, login_username, login_password FROM credentials WHERE user_id = ?", (user_id,))
        credentials = c.fetchall()
        decrypted_credentials = [
            (cred[0], cred[1], cred[2], decrypt_password(cred[3])) for cred in credentials
        ]
    return render_template('dashboard.html', credentials=decrypted_credentials, username=session['username'])

@app.route('/view-password/<int:cred_id>', methods=['GET', 'POST'])
def view_password(cred_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    error = None
    password = None

    if request.method == 'POST':
        master_password = request.form['master_password']

        with sqlite3.connect('password_manager.db') as conn:
            c = conn.cursor()

            c.execute("SELECT hashed_password, registration_datetime FROM users WHERE id = ?", (session['user_id'],))
            result = c.fetchone()
            stored_hash = result[0]
            time = result[1]
            salt = generate_salt(master_password, time)
            mid = len(salt) // 2
            check_hash = sha256(salt[:mid] + master_password + salt[mid:])

            if check_hash != stored_hash:
                error = "Incorrect password"
            else:
                c.execute("SELECT login_password FROM credentials WHERE id = ? AND user_id = ?", (cred_id, session['user_id']))
                result = c.fetchone()
                if not result:
                    error = "Credential not found."
                else:
                    encrypted_pw = result[0]
                    password = decrypt_password(encrypted_pw)

    return render_template('show_password.html', cred_id=cred_id, error=error, password=password)

@app.route('/edit/<int:cred_id>', methods=['GET', 'POST'])
def edit_credential(cred_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    error = None
    success = None

    with sqlite3.connect('password_manager.db') as conn:
        c = conn.cursor()

        # Fetch existing credential
        c.execute("SELECT site, login_username, login_password FROM credentials WHERE id = ? AND user_id = ?",
                  (cred_id, session['user_id']))
        result = c.fetchone()

        if not result:
            return "Credential not found."

        site, login_username, encrypted_password = result

        if request.method == 'POST':
            current_password_input = request.form['current_password']
            new_username = request.form['new_username']
            new_password = request.form['new_password']

            decrypted_password = decrypt_password(encrypted_password)

            if current_password_input != decrypted_password:
                error = "Current password is incorrect."
            else:
                encrypted_new_password = encrypt_password(new_password)
                c.execute('''UPDATE credentials 
                             SET site = ?, login_username = ?, login_password = ? 
                             WHERE id = ? AND user_id = ?''',
                          (site, new_username, encrypted_new_password, cred_id, session['user_id']))
                conn.commit()
                success = "Credential updated successfully."

    return render_template("edit.html",
                           site=site,
                           login_username=login_username,
                           cred_id=cred_id,
                           error=error,
                           success=success)

@app.route('/delete/<int:cred_id>')
def delete_credential(cred_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('password_manager.db') as conn:
        c = conn.cursor()
        c.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        conn.commit()
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
