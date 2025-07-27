import string
import secrets

lowercase = string.ascii_lowercase
uppercase = string.ascii_uppercase
digits = string.digits
symbols = string.punctuation

all_chars = lowercase + uppercase + digits + symbols

password_length = 8
password = "OB&r[^CMtg,Y"
#password = ''.join(secrets.choice(all_chars) for _ in range(password_length))

def lcg_salt_generator(password: str, salt_length: int = 16) -> str:
    # Convert password into a numeric seed (e.g., sum of ASCII values)
    seed = sum(ord(char) for char in password)

    # LCG constants (these can be tweaked for stronger randomness)
    a = 1103515245
    c = 12345
    m = 2**31

    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    salt = ""

    for _ in range(salt_length):
        seed = (a * seed + c) % m
        salt += charset[seed % len(charset)]

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

    # Preprocessing: convert to binary
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

generated_salt = lcg_salt_generator(password)
print("Generated password:", password)
print("Generated Salt:", generated_salt)

mid = len(generated_salt) // 2
hash_input = generated_salt[:mid] + password + generated_salt[mid:]
print("Hash input:", hash_input)

hashed_value = sha256(hash_input)
print("SHA-256 Hash:", hashed_value)
