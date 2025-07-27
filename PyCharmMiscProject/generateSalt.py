def custom_prng(seed):
    a = 1103515245
    c = 12345
    m = 2**31
    return (a * seed + c) % m

def generate_salt(length, seed=123456):
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    salt = ""
    current = seed
    for _ in range(length):
        current = custom_prng(current)
        salt += charset[current % len(charset)]
    return salt

print("Generated Salt:", generate_salt(16))
