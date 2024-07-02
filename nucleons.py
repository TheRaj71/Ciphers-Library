import random
import string
import base64
from typing import List, Tuple, Callable
from Crypto.Cipher import Blowfish, DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

def caesar_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    shift = sum(ord(c) for c in key) % 26
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            shift_amount = shift if mode == 'encrypt' else -shift
            result += chr((ord(char) - ascii_offset + shift_amount) % 26 + ascii_offset)
        else:
            result += char
    return result

def vigenere_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    result = ""
    key = key.upper()
    key_index = 0
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            key_shift = ord(key[key_index % len(key)]) - ord('A')
            shift_amount = key_shift if mode == 'encrypt' else -key_shift
            result += chr((ord(char) - ascii_offset + shift_amount) % 26 + ascii_offset)
            key_index += 1
        else:
            result += char
    return result

def simple_substitution_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    alphabet = string.ascii_uppercase
    key = ''.join(dict.fromkeys(key.upper() + alphabet))[:26]
    if mode == 'encrypt':
        trans_table = str.maketrans(alphabet, key)
    else:
        trans_table = str.maketrans(key, alphabet)
    return text.translate(trans_table)

def atbash_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    alphabet = string.ascii_lowercase
    reverse_alphabet = alphabet[::-1]
    trans_table = str.maketrans(alphabet + alphabet.upper(), reverse_alphabet + reverse_alphabet.upper())
    return text.translate(trans_table)

def rot13_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    return caesar_cipher(text, '13', mode)

def base64_encode_decode(text: str, key: str, mode: str = 'encrypt') -> str:
    if mode == 'encrypt':
        return base64.b64encode(text.encode()).decode()
    else:
        return base64.b64decode(text.encode()).decode()

def morse_code_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    morse_code_dict = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.', ' ': '/'
    }
    if mode == 'encrypt':
        return ' '.join(morse_code_dict.get(char.upper(), char) for char in text)
    else:
        morse_to_char = {v: k for k, v in morse_code_dict.items()}
        return ''.join(morse_to_char.get(code, code) for code in text.split())

def rail_fence_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    rails = max(2, min(10, sum(ord(c) for c in key) % 10))
    fence = [[None] * len(text) for _ in range(rails)]
    rail = 0
    direction = 1
    for i, char in enumerate(text):
        fence[rail][i] = char
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    if mode == 'encrypt':
        return ''.join(char for rail in fence for char in rail if char)
    else:
        positions = sorted([(i, j) for i in range(rails) for j in range(len(text)) if fence[i][j] is not None])
        return ''.join(fence[i][j] for i, j in positions)

def affine_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    a, b = sum(ord(c) for c in key[:len(key)//2]) % 25 + 1, sum(ord(c) for c in key[len(key)//2:]) % 26
    if mode == 'encrypt':
        return ''.join(chr((a * (ord(char.upper()) - 65) + b) % 26 + 65) if char.isalpha() else char for char in text)
    else:
        a_inv = pow(a, -1, 26)
        return ''.join(chr((a_inv * ((ord(char.upper()) - 65) - b)) % 26 + 65) if char.isalpha() else char for char in text)

def polybius_square_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    alphabet = ''.join(dict.fromkeys(key.upper() + string.ascii_uppercase.replace('J', '')))
    square = {char: f"{i//5+1}{i%5+1}" for i, char in enumerate(alphabet)}
    if mode == 'encrypt':
        return ' '.join(square.get(char.upper(), char) for char in text if char.upper() in square)
    else:
        inv_square = {v: k for k, v in square.items()}
        return ''.join(inv_square.get(text[i:i+2], ' ') for i in range(0, len(text), 2))

def running_key_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    key = key * (len(text) // len(key) + 1)
    result = ""
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i].upper()) - ord('A')
            if mode == 'encrypt':
                result += chr((ord(char.upper()) - 65 + shift) % 26 + 65)
            else:
                result += chr((ord(char.upper()) - 65 - shift) % 26 + 65)
        else:
            result += char
    return result

def columnar_transposition_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    if mode == 'encrypt':
        padding = (len(key) - len(text) % len(key)) % len(key)
        text += ' ' * padding
        grid = [text[i:i+len(key)] for i in range(0, len(text), len(key))]
        return ''.join(''.join(row[i] for row in grid) for i in key_order)
    else:
        columns = [text[i::len(key)] for i in range(len(key))]
        return ''.join(''.join(columns[key_order.index(i)][j] for i in range(len(key)))
                       for j in range(len(text)//len(key))).rstrip()

def autokey_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    key = key.upper()
    if mode == 'encrypt':
        full_key = (key + text.upper())[:len(text)]
    else:
        full_key = key
        for i in range(len(text) - len(key)):
            full_key += chr((ord(text[i].upper()) - ord(full_key[i]) + 26) % 26 + 65)
    return ''.join(chr((ord(char.upper()) - 65 + (ord(full_key[i]) - 65) if mode == 'encrypt' else -ord(full_key[i]) + 65) % 26 + 65)
                   if char.isalpha() else char for i, char in enumerate(text))

def blowfish_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    cipher = Blowfish.new(key.encode(), Blowfish.MODE_ECB)
    if mode == 'encrypt':
        padded_text = pad(text.encode(), Blowfish.block_size)
        return base64.b64encode(cipher.encrypt(padded_text)).decode()
    else:
        decrypted_data = cipher.decrypt(base64.b64decode(text))
        return unpad(decrypted_data, Blowfish.block_size).decode()

def triple_des_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    key = key.encode()[:24].ljust(24, b'\0')
    cipher = DES3.new(key, DES3.MODE_ECB)
    if mode == 'encrypt':
        padded_text = pad(text.encode(), DES3.block_size)
        return base64.b64encode(cipher.encrypt(padded_text)).decode()
    else:
        decrypted_data = cipher.decrypt(base64.b64decode(text))
        return unpad(decrypted_data, DES3.block_size).decode()

def twofish_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    # Twofish is not available in pycryptodome, so we'll use AES as a substitute
    return aes_cipher(text, key, mode)

def idea_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    # IDEA is not available in pycryptodome, so we'll use AES as a substitute
    return aes_cipher(text, key, mode)

def aes_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    key = pad(key.encode(), AES.block_size)
    cipher = AES.new(key, AES.MODE_ECB)
    if mode == 'encrypt':
        padded_text = pad(text.encode(), AES.block_size)
        return base64.b64encode(cipher.encrypt(padded_text)).decode()
    else:
        decrypted_data = cipher.decrypt(base64.b64decode(text))
        return unpad(decrypted_data, AES.block_size).decode()

def rsa_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    # For simplicity, we'll use a fixed RSA key pair
    rsa_key = RSA.generate(2048)
    if mode == 'encrypt':
        cipher = PKCS1_OAEP.new(rsa_key.publickey())
        return base64.b64encode(cipher.encrypt(text.encode())).decode()
    else:
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.decrypt(base64.b64decode(text)).decode()

def hmac_algorithm(text: str, key: str, mode: str = 'encrypt') -> str:
    h = HMAC.new(key.encode(), digestmod=SHA256)
    h.update(text.encode())
    return h.hexdigest()

ALGORITHMS = [
    (1, caesar_cipher), (2, vigenere_cipher), (3, simple_substitution_cipher),
    (4, atbash_cipher), (5, rot13_cipher), (6, base64_encode_decode),
    (7, morse_code_cipher), (8, rail_fence_cipher), (9, affine_cipher),
    (10, polybius_square_cipher), (11, running_key_cipher), (12, columnar_transposition_cipher),
    (13, autokey_cipher), (14, blowfish_cipher), (15, triple_des_cipher),
    (16, twofish_cipher), (17, idea_cipher), (18, aes_cipher),
    (19, rsa_cipher), (20, hmac_algorithm)
]

def nucleons_x_cipher(text: str, master_key: str, mode: str = 'encrypt') -> str:
    # Always start with algorithms 3, 6, and 9
    sequence = [3, 6, 9]
    
    # Add remaining algorithms in random order
    remaining = [i for i in range(1, 21) if i not in sequence]
    random.shuffle(remaining)
    sequence.extend(remaining)

    # Generate sub-keys from the master key
    sub_keys = [SHA256.new(data=(master_key + str(i)).encode()).hexdigest() for i in range(20)]

    # Apply each algorithm in the sequence
    for algo_index in sequence:
        algo = next(a for i, a in ALGORITHMS if i == algo_index)
        text = algo(text, sub_keys[algo_index - 1], mode)

    return text

def main():
    print("Nucleons-X Encryption System")
    print("WARNING: This is for educational purposes only. Do not use for real security needs.")
    
    mode = input("Choose mode (encrypt/decrypt): ").lower()
    text = input("Enter the text: ")
    master_key = input("Enter the master key: ")

    result = nucleons_x_cipher(text, master_key, mode)
    print(f"\nResult: {result}")

if __name__ == "__main__":
    main()
