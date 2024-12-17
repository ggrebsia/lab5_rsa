import tkinter as tk
from tkinter import messagebox
import random

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def primer(x):
    if x < 2:
        return False
    for i in range(2, int(x**0.5) + 1):
        if x % i == 0:
            return False
    return True

def prime_generate(len):
    p = random.getrandbits(len)
    p |= (1 << len - 1) | 1
    return p

def prime_generate_number(len):
    p = prime_generate(len) 
    while not primer(p):
        p = prime_generate(len)
    return p

def generate_keys():
    p = prime_generate_number(8)
    q = prime_generate_number(8)
    f = (p - 1) * (q - 1)
    n = p*q
    e = random.randrange(2, f)
    while gcd(e, f) != 1:
        e = random.randrange(2, f)

    d = pow(e, -1, f)

    return (e, n), (d, n)

def encrypt(plaintext, public_key):
    e, n = public_key
    ciphertext = []
    for char in plaintext:
        char_int = ord(char)
        cipher_int = pow(char_int, e, n)
        ciphertext.append(cipher_int)
    return ciphertext

def decrypt(ciphertext, private_key):
    d, n = private_key
    return ''.join([chr(pow(char, d, n)) for char in ciphertext])

public_key, private_key = generate_keys()

def on_encrypt():
    text = plaintext_entry.get()
    cipher = encrypt(text, public_key)
    ciphertext_entry.delete(0, tk.END)
    ciphertext_entry.insert(0, str(cipher))

def on_decrypt():
    ciphertext_str = ciphertext_entry.get()
    try:
        ciphertext = [int(x) for x in ciphertext_str.strip('[]').split(', ')]
    except ValueError:
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "Ошибка\n")
        return

    decrypted_text = decrypt(ciphertext, private_key)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, decrypted_text)

root = tk.Tk()
root.title("rsa")

tk.Label(root, text="Исходный текст:").grid(row=0, column=0, padx=10, pady=10)
plaintext_entry = tk.Entry(root, width=40)
plaintext_entry.grid(row=0, column=1, padx=10, pady=10)

encrypt_button = tk.Button(root, text="Зашифровать", command=on_encrypt)
encrypt_button.grid(row=2, column=0, padx=10, pady=10)

tk.Label(root, text="Зашифрованный текст:").grid(row=3, column=0, padx=10, pady=10)
ciphertext_entry = tk.Entry(root, width=40)
ciphertext_entry.grid(row=3, column=1, padx=10, pady=10)

decrypt_button = tk.Button(root, text="Расшифровать", command=on_decrypt)
decrypt_button.grid(row=4, column=0, padx=10, pady=10)

tk.Label(root, text="Результат:").grid(row=5, column=0, padx=10, pady=10)
result_text = tk.Text(root, height=5, width=40)
result_text.grid(row=5, column=1, padx=10, pady=10)

root.mainloop()