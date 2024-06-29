import random
import string
from typing import Callable
import base64
from Crypto.Cipher import Blowfish, DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

def caesar_cipher(text: str, shift: int, mode: str = 'encrypt') -> str:
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
    if mode == 'encrypt':
        trans_table = str.maketrans(alphabet, key.upper())
    else:
        trans_table = str.maketrans(key.upper(), alphabet)
    return text.translate(trans_table)

def atbash_cipher(text: str, *args, **kwargs) -> str:
    alphabet = string.ascii_lowercase
    reverse_alphabet = alphabet[::-1]
    trans_table = str.maketrans(alphabet + alphabet.upper(), reverse_alphabet + reverse_alphabet.upper())
    return text.translate(trans_table)

def rot13_cipher(text: str, *args, **kwargs) -> str:
    return caesar_cipher(text, 13, 'encrypt')

def base64_encode_decode(text: str, mode: str = 'encrypt') -> str:
    if mode == 'encrypt':
        return base64.b64encode(text.encode()).decode()
    else:
        return base64.b64decode(text.encode()).decode()

def morse_code_cipher(text: str, mode: str = 'encrypt') -> str:
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

def rail_fence_cipher(text: str, key: int, mode: str = 'encrypt') -> str:
    def encrypt(text, key):
        fence = [[None] * len(text) for _ in range(key)]
        rail = 0
        direction = 1
        for i, char in enumerate(text):
            fence[rail][i] = char
            rail += direction
            if rail == 0 or rail == key - 1:
                direction *= -1
        return ''.join(char for rail in fence for char in rail if char)

    def decrypt(text, key):
        fence = [[None] * len(text) for _ in range(key)]
        rail = 0
        direction = 1
        for i in range(len(text)):
            fence[rail][i] = '*'
            rail += direction
            if rail == 0 or rail == key - 1:
                direction *= -1
        index = 0
        for i in range(key):
            for j in range(len(text)):
                if fence[i][j] == '*':
                    fence[i][j] = text[index]
                    index += 1
        rail = 0
        direction = 1
        result = []
        for i in range(len(text)):
            result.append(fence[rail][i])
            rail += direction
            if rail == 0 or rail == key - 1:
                direction *= -1
        return ''.join(result)

    if mode == 'encrypt':
        return encrypt(text, key)
    else:
        return decrypt(text, key)

def affine_cipher(text: str, key: tuple, mode: str = 'encrypt') -> str:
    def encrypt(char, a, b):
        if char.isalpha():
            return chr((a * (ord(char.upper()) - 65) + b) % 26 + 65)
        return char

    def decrypt(char, a, b):
        if char.isalpha():
            return chr(((pow(a, -1, 26) * (ord(char.upper()) - 65 - b)) % 26) + 65)
        return char

    a, b = key
    if mode == 'encrypt':
        return ''.join(encrypt(char, a, b) for char in text)
    else:
        return ''.join(decrypt(char, a, b) for char in text)

def polybius_square_cipher(text: str, key: str = 'ABCDEFGHIKLMNOPQRSTUVWXYZ', mode: str = 'encrypt') -> str:
    def create_square(key):
        return {char: f"{i//5+1}{i%5+1}" for i, char in enumerate(key)}

    square = create_square(key)
    inv_square = {v: k for k, v in square.items()}

    if mode == 'encrypt':
        return ' '.join(square.get(char.upper(), char) for char in text if char.upper() in square)
    else:
        return ''.join(inv_square.get(pair, pair) for pair in text.split())

def running_key_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            key_char = key[key_index % len(key)].upper()
            shift = ord(key_char) - ord('A')
            if mode == 'encrypt':
                encrypted_char = chr((ord(char.upper()) - 65 + shift) % 26 + 65)
            else:
                encrypted_char = chr((ord(char.upper()) - 65 - shift) % 26 + 65)
            result += encrypted_char.lower() if char.islower() else encrypted_char
            key_index += 1
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
    result = ""
    key = key.upper()
    if mode == 'encrypt':
        full_key = (key + text.upper())[:len(text)]
    else:
        full_key = key
        for i in range(len(text) - len(key)):
            full_key += chr((ord(text[i].upper()) - ord(full_key[i]) + 26) % 26 + 65)

    for i, char in enumerate(text):
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            shift = ord(full_key[i]) - ord('A')
            if mode == 'encrypt':
                result += chr((ord(char.upper()) - 65 + shift) % 26 + ascii_offset)
            else:
                result += chr((ord(char.upper()) - 65 - shift) % 26 + ascii_offset)
        else:
            result += char
    return result

def blowfish_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    def encrypt(plaintext, key):
        cipher = Blowfish.new(key.encode(), Blowfish.MODE_ECB)
        padded_text = pad(plaintext.encode(), Blowfish.block_size)
        ciphertext = cipher.encrypt(padded_text)
        return base64.b64encode(ciphertext).decode()

    def decrypt(ciphertext, key):
        cipher = Blowfish.new(key.encode(), Blowfish.MODE_ECB)
        decrypted_data = cipher.decrypt(base64.b64decode(ciphertext))
        return unpad(decrypted_data, Blowfish.block_size).decode()

    if mode == 'encrypt':
        return encrypt(text, key)
    else:
        return decrypt(text, key)
    

def triple_des_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    def encrypt(plaintext, key):
        cipher = DES3.new(key.encode()[:24], DES3.MODE_ECB)
        padded_text = pad(plaintext.encode(), DES3.block_size)
        ciphertext = cipher.encrypt(padded_text)
        return base64.b64encode(ciphertext).decode()

    def decrypt(ciphertext, key):
        cipher = DES3.new(key.encode()[:24], DES3.MODE_ECB)
        decrypted_data = cipher.decrypt(base64.b64decode(ciphertext))
        return unpad(decrypted_data, DES3.block_size).decode()

    if mode == 'encrypt':
        return encrypt(text, key)
    else:
        return decrypt(text, key)

def twofish_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    
    # It is a placeholder implementation using AES as a substitute.
    return aes_cipher(text, key, mode)

def idea_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    
    # itss is a placeholder implementation using AES as a substitute.
    return aes_cipher(text, key, mode)

def aes_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    def encrypt(plaintext, key):
        cipher = AES.new(pad(key.encode(), AES.block_size), AES.MODE_ECB)
        padded_text = pad(plaintext.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        return base64.b64encode(ciphertext).decode()

    def decrypt(ciphertext, key):
        cipher = AES.new(pad(key.encode(), AES.block_size), AES.MODE_ECB)
        decrypted_data = cipher.decrypt(base64.b64decode(ciphertext))
        return unpad(decrypted_data, AES.block_size).decode()

    if mode == 'encrypt':
        return encrypt(text, key)
    else:
        return decrypt(text, key)

def rsa_cipher(text: str, key: str, mode: str = 'encrypt') -> str:
    def generate_key_pair():
        key = RSA.generate(2048)
        private_key = key.export_key().decode()
        public_key = key.publickey().export_key().decode()
        return private_key, public_key

    def encrypt(plaintext, public_key):
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(plaintext.encode())
        return base64.b64encode(ciphertext).decode()

    def decrypt(ciphertext, private_key):
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        decrypted_data = cipher.decrypt(base64.b64decode(ciphertext))
        return decrypted_data.decode()

    if mode == 'encrypt':
        if key == 'generate':
            private_key, public_key = generate_key_pair()
            print(f"Generated private key:\n{private_key}\n")
            print(f"Generated public key:\n{public_key}\n")
            return encrypt(text, public_key)
        else:
            return encrypt(text, key)
    else:
        return decrypt(text, key)

def hmac_algorithm(text: str, key: str, mode: str = 'encrypt') -> str:
    # Note: HMAC is not an encryption algorithm, but a method for message authentication although i have added it
    h = HMAC.new(key.encode(), digestmod=SHA256)
    h.update(text.encode())
    return h.hexdigest()

def generate_substitution_key() -> str:
    alphabet = list(string.ascii_uppercase)
    random.shuffle(alphabet)
    return ''.join(alphabet)

ALGORITHMS = {
    'caesar': caesar_cipher,
    'vigenere': vigenere_cipher,
    'substitution': simple_substitution_cipher,
    'atbash': atbash_cipher,
    'rot13': rot13_cipher,
    'base64': base64_encode_decode,
    'morse': morse_code_cipher,
    'rail_fence': rail_fence_cipher,
    'affine': affine_cipher,
    'polybius': polybius_square_cipher,
    'running_key': running_key_cipher,
    'columnar': columnar_transposition_cipher,
    'autokey': autokey_cipher,
    'blowfish': blowfish_cipher,
    'triple_des': triple_des_cipher,
    'twofish': twofish_cipher,
    'idea': idea_cipher,
    'aes': aes_cipher,
    'rsa': rsa_cipher,
    'hmac': hmac_algorithm
}

def encrypt_decrypt(algorithm: Callable, text: str, key, mode: str) -> str:
    return algorithm(text, key, mode)

def main():
    print("""
    ╔═══════════════════════════════════════════╗
    ║    Advanced Multi-Algorithm Crypto Tool   ║
    ╚═══════════════════════════════════════════╝
    """)

    while True:
        print("\nAvailable algorithms:")
        for i, algo in enumerate(ALGORITHMS.keys(), 1):
            print(f"{i}. {algo.capitalize()}")

        choice = input("\nSelect an algorithm (or 'q' to quit): ").lower()
        if choice == 'q':
            print("Goodbye!")
            break

        if choice.isdigit() and 1 <= int(choice) <= len(ALGORITHMS):
            algorithm = list(ALGORITHMS.keys())[int(choice) - 1]
        elif choice in ALGORITHMS:
            algorithm = choice
        else:
            print("Invalid choice. Please try again.")
            continue

        mode = input("Choose mode (encrypt/decrypt): ").lower()
        if mode not in ['encrypt', 'decrypt']:
            print("Invalid mode. Please choose 'encrypt' or 'decrypt'.")
            continue

        text = input("Enter the text: ")

        if algorithm in ['caesar', 'rail_fence']:
            key = int(input("Enter the key (an integer): "))
        elif algorithm in ['vigenere', 'running_key', 'columnar', 'autokey', 'blowfish', 'triple_des', 'twofish', 'idea', 'aes', 'hmac']:
            key = input("Enter the key (a word or phrase): ")
        elif algorithm == 'substitution':
            if mode == 'encrypt':
                use_random = input("Use a random key? (y/n): ").lower() == 'y'
                if use_random:
                    key = generate_substitution_key()
                    print(f"Generated key: {key}")
                else:
                    key = input("Enter the substitution key (26 unique uppercase letters): ")
            else:
                key = input("Enter the substitution key used for encryption: ")
        elif algorithm == 'affine':
            a = int(input("Enter the 'a' value for the affine cipher: "))
            b = int(input("Enter the 'b' value for the affine cipher: "))
            key = (a, b)
        elif algorithm == 'polybius':
            use_default = input("Use default Polybius square? (y/n): ").lower() == 'y'
            if use_default:
                key = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
            else:
                key = input("Enter the Polybius square key (25 unique uppercase letters): ")
        elif algorithm == 'rsa':
            if mode == 'encrypt':
                generate_new = input("Generate new RSA key pair? (y/n): ").lower() == 'y'
                if generate_new:
                    key = 'generate'
                else:
                    key = input("Enter the public key: ")
            else:
                key = input("Enter the private key: ")
        else:
            key = None

        result = encrypt_decrypt(ALGORITHMS[algorithm], text, key, mode)
        print(f"\nResult: {result}")

if __name__ == "__main__":
    main()