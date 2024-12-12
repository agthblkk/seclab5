import tkinter as tk
from tkinter import messagebox, filedialog
import random
import math

def generate_keys():
    global private_key, public_key, m, t, t_inv


    n = 200  # збільшений розмір, щоб можна було шифрувати більші повідомлення
    B = [random.randint(1, 10)]
    for _ in range(1, n):
        B.append(random.randint(sum(B) + 1, sum(B) * 2))

    m = sum(B) + random.randint(1, 10)
    t = random.randint(2, m - 1)


    while math.gcd(t, m) != 1:
        t = random.randint(2, m - 1)


    t_inv = pow(t, -1, m)


    A = [(b * t) % m for b in B]

    private_key = (B, m, t, t_inv)
    public_key = A

    messagebox.showinfo(translations[language]['keys_generated_title'], translations[language]['keys_generated_msg'])


def encrypt_message():
    global public_key

    message = message_input.get()
    if not message:
        messagebox.showerror(translations[language]['error_title'], translations[language]['error_no_message'])
        return

    # Кодуємо повідомлення в UTF-8
    message_bytes = message.encode('utf-8')
    binary_message = ''.join(format(byte, '08b') for byte in message_bytes)
    binary_list = [int(bit) for bit in binary_message]

    print(f'Binary message during encryption: {binary_list}')

    if len(binary_list) > len(public_key):
        messagebox.showerror(translations[language]['error_title'], translations[language]['error_message_too_long'])
        return

    encrypted_message = sum(bit * public_key[i] for i, bit in enumerate(binary_list))
    encrypted_message_output.set(str(encrypted_message))


def decrypt_message():
    global private_key

    encrypted_message_str = encrypted_message_input.get()
    if not encrypted_message_str:
        messagebox.showerror(translations[language]['error_title'], translations[language]['error_no_encrypted_message'])
        return

    try:
        encrypted_message = int(encrypted_message_str)
    except ValueError:
        messagebox.showerror(translations[language]['error_title'], translations[language]['error_invalid_encrypted_message'])
        return

    B, m, _, t_inv = private_key

    # Дешифрування з використанням оберненого t
    S = (encrypted_message * t_inv) % m
    print(f'Decoded S value: {S}')

    # Розв'язання задачі суперзростаючого рюкзака
    binary_message_list = []
    for b in reversed(B):
        if S >= b:
            binary_message_list.insert(0, '1')
            S -= b
        else:
            binary_message_list.insert(0, '0')

    binary_message = ''.join(binary_message_list)
    print(f'Binary message before byte reconstruction: {binary_message}')

    if len(binary_message) % 8 != 0:
        while len(binary_message) % 8 != 0:
            binary_message = binary_message[1:]

    print(f'Binary message after alignment: {binary_message}')

    byte_values = [int(binary_message[i:i+8], 2) for i in range(0, len(binary_message), 8)]
    decrypted_bytes = bytes(byte_values)

    try:
        decrypted_message = decrypted_bytes.decode('utf-8', errors='replace')
        print(f'Decrypted message: {decrypted_message}')
        decrypted_message_output.set(decrypted_message)
    except ValueError:
        messagebox.showerror(translations[language]['error_title'], translations[language]['error_invalid_unicode'])
        return


def select_file_for_encryption():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'r', encoding='utf-8') as file:
            message_input.delete(0, tk.END)
            message_input.insert(0, file.read())


def select_file_for_decryption():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'r', encoding='utf-8') as file:
            encrypted_message_input.delete(0, tk.END)
            encrypted_message_input.insert(0, file.read())


def save_encrypted_message():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(encrypted_message_output.get())


def save_decrypted_message():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(decrypted_message_output.get())


def switch_language():
    global language
    language = 'ua' if language == 'en' else 'en'
    update_ui_text()


def update_ui_text():
    generate_keys_button.config(text=translations[language]['generate_keys'])
    encrypt_label.config(text=translations[language]['message_to_encrypt'])
    encrypt_button.config(text=translations[language]['encrypt'])
    encrypted_message_label.config(text=translations[language]['encrypted_message'])
    decrypt_label.config(text=translations[language]['encrypted_message_to_decrypt'])
    decrypt_button.config(text=translations[language]['decrypt'])
    decrypted_message_label.config(text=translations[language]['decrypted_message'])
    language_button.config(text=translations[language]['switch_language'])
    file_encrypt_button.config(text=translations[language]['select_file_encrypt'])
    file_decrypt_button.config(text=translations[language]['select_file_decrypt'])
    save_encrypted_button.config(text=translations[language]['save_encrypted'])
    save_decrypted_button.config(text=translations[language]['save_decrypted'])


# Translations
translations = {
    'en': {
        'generate_keys': "Generate Keys",
        'keys_generated_title': "Keys Generated",
        'keys_generated_msg': "Public and private keys have been generated.",
        'message_to_encrypt': "Message to Encrypt:",
        'encrypt': "Encrypt",
        'encrypted_message': "Encrypted Message:",
        'encrypted_message_to_decrypt': "Encrypted Message to Decrypt:",
        'decrypt': "Decrypt",
        'decrypted_message': "Decrypted Message:",
        'switch_language': "Switch to Ukrainian",
        'error_title': "Error",
        'error_no_message': "Please enter a message to encrypt.",
        'error_message_too_long': "Message is too long to encrypt.",
        'error_no_encrypted_message': "Please enter an encrypted message to decrypt.",
        'error_invalid_encrypted_message': "Encrypted message must be an integer.",
        'error_invalid_unicode': "Decrypted message contains invalid Unicode characters.",
        'select_file_encrypt': "Select File for Encryption",
        'select_file_decrypt': "Select File for Decryption",
        'save_encrypted': "Save Encrypted Message",
        'save_decrypted': "Save Decrypted Message",
    },
    'ua': {
        'generate_keys': "Згенерувати ключі",
        'keys_generated_title': "Ключі згенеровано",
        'keys_generated_msg': "Публічний і приватний ключі згенеровано.",
        'message_to_encrypt': "Повідомлення для шифрування:",
        'encrypt': "Зашифрувати",
        'encrypted_message': "Зашифроване повідомлення:",
        'encrypted_message_to_decrypt': "Зашифроване повідомлення для дешифрування:",
        'decrypt': "Дешифрувати",
        'decrypted_message': "Дешифроване повідомлення:",
        'switch_language': "Переключити на англійську",
        'error_title': "Помилка",
        'error_no_message': "Будь ласка, введіть повідомлення для шифрування.",
        'error_message_too_long': "Повідомлення занадто довге для шифрування.",
        'error_no_encrypted_message': "Будь ласка, введіть зашифроване повідомлення для дешифрування.",
        'error_invalid_encrypted_message': "Зашифроване повідомлення повинно бути цілим числом.",
        'error_invalid_unicode': "Дешифроване повідомлення містить некоректні символи Unicode.",
        'select_file_encrypt': "Обрати файл для шифрування",
        'select_file_decrypt': "Обрати файл для дешифрування",
        'save_encrypted': "Зберегти зашифроване повідомлення",
        'save_decrypted': "Зберегти дешифроване повідомлення",
    }
}


language = 'en'


root = tk.Tk()
root.title("Knapsack Cryptosystem")


key_frame = tk.Frame(root)
key_frame.pack(pady=10)

encrypt_frame = tk.Frame(root)
encrypt_frame.pack(pady=10)

decrypt_frame = tk.Frame(root)
decrypt_frame.pack(pady=10)


generate_keys_button = tk.Button(key_frame, text="Generate Keys", command=generate_keys)
generate_keys_button.pack()


encrypt_label = tk.Label(encrypt_frame, text="Message to Encrypt:")
encrypt_label.pack()
message_input = tk.Entry(encrypt_frame, width=40)
message_input.pack()

file_encrypt_button = tk.Button(encrypt_frame, text="Select File for Encryption", command=select_file_for_encryption)
file_encrypt_button.pack()

encrypt_button = tk.Button(encrypt_frame, text="Encrypt", command=encrypt_message)
encrypt_button.pack()

encrypted_message_output = tk.StringVar()
encrypted_message_label = tk.Label(encrypt_frame, text="Encrypted Message:")
encrypted_message_label.pack()
tk.Entry(encrypt_frame, textvariable=encrypted_message_output, state="readonly", width=40).pack()

save_encrypted_button = tk.Button(encrypt_frame, text="Save Encrypted Message", command=save_encrypted_message)
save_encrypted_button.pack()

# Decryption
decrypt_label = tk.Label(decrypt_frame, text="Encrypted Message to Decrypt:")
decrypt_label.pack()
encrypted_message_input = tk.Entry(decrypt_frame, width=40)
encrypted_message_input.pack()

file_decrypt_button = tk.Button(decrypt_frame, text="Select File for Decryption", command=select_file_for_decryption)
file_decrypt_button.pack()

decrypt_button = tk.Button(decrypt_frame, text="Decrypt", command=decrypt_message)
decrypt_button.pack()

decrypted_message_output = tk.StringVar()
decrypted_message_label = tk.Label(decrypt_frame, text="Decrypted Message:")
decrypted_message_label.pack()
tk.Entry(decrypt_frame, textvariable=decrypted_message_output, state="readonly", width=40).pack()

save_decrypted_button = tk.Button(decrypt_frame, text="Save Decrypted Message", command=save_decrypted_message)
save_decrypted_button.pack()


language_button = tk.Button(root, text="Switch to Ukrainian", command=switch_language)
language_button.pack(pady=10)


update_ui_text()

root.mainloop()
