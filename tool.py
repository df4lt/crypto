import hashlib
import re
import pyfiglet
import time
from colorama import init, Fore, Style
import math
init()

colors = {
    "cyan": "\033[1;36m"
}

def color(text, color):
    return colors[color] + text + "\033[0m"


def hash_types(hash_value):
    supported_algorithms = hashlib.algorithms_available
    for algorithm in supported_algorithms:
        try:
            hash_object = getattr(hashlib, algorithm)()
            hash_object.update(b"")
            hash_object.hexdigest()
            if len(hash_value) == len(hash_object.hexdigest()):
                return algorithm
        except:
            pass
    return "Unknown"


def encryption():
    while True:
        p('_________________________________')
        try:
            cypher = int(input(color("【𝟭】Caesar\n【𝟮】Rotor Cipher\n【𝟯】monoalphabetic\n【𝟰】Play fair\n【99】Back  \nEnter your choice : ", 'cyan')))
            p('_________________________________')
            if cypher == 1:
                def encrypt_caesar(plaintext, shift):
                    encrypted_text = ""
                    for char in plaintext:
                        if char.isalpha():
                            ascii_offset = ord('A') if char.isupper() else ord('a')
                            encrypted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                            encrypted_text += encrypted_char
                        else:
                            encrypted_text += char
                    return encrypted_text

                plaintext = input("enter the message : ")
                shift = int(input("Please enter an amount the shift : "))
                encrypted_text = encrypt_caesar(plaintext, shift)
                p("Encrypted text : " + encrypted_text)

            elif cypher == 2:
                class RotorCipher:
                    def __init__(self, rotor_settings):
                        self.rotor_settings = rotor_settings

                    def encrypt(self, plaintext):
                        ciphertext = ""
                        for char in plaintext:
                            if char.isalpha():
                                char = char.upper()
                                if char in self.rotor_settings:
                                    char = self.rotor_settings[char]
                            ciphertext += char
                        return ciphertext

                    def decrypt(self, ciphertext):
                        decrypted_text = ""
                        reverse_rotor_settings = {v: k for k, v in self.rotor_settings.items()}
                        for char in ciphertext:
                            if char.isalpha():
                                char = char.upper()
                                if char in reverse_rotor_settings:
                                    char = reverse_rotor_settings[char]
                            decrypted_text += char
                        return decrypted_text

                rotor_settings = {
                    'A': 'M', 'B': 'N', 'C': 'B', 'D': 'V', 'E': 'C', 'F': 'X',
                    'G': 'Z', 'H': 'A', 'I': 'S', 'J': 'D', 'K': 'F', 'L': 'G',
                    'M': 'H', 'N': 'J', 'O': 'K', 'P': 'L', 'Q': 'P', 'R': 'O',
                    'S': 'I', 'T': 'U', 'U': 'Y', 'V': 'T', 'W': 'R', 'X': 'E',
                    'Y': 'W', 'Z': 'Q'
                }

                cipher = RotorCipher(rotor_settings)

                plaintext = input("enter the message : ")

                encrypted_text = cipher.encrypt(plaintext)
                p("Encrypted text : " + encrypted_text)

            elif cypher == 3:
                def monoalphabetic_cipher_encrypt(plaintext):
                    substitution = {
                        'A': 'E', 'B': 'G', 'C': 'R', 'D': 'T', 'E': 'K',
                        'F': 'P', 'G': 'Y', 'H': 'O', 'I': 'L', 'J': 'X',
                        'K': 'A', 'L': 'M', 'M': 'N', 'N': 'C', 'O': 'U',
                        'P': 'B', 'Q': 'D', 'R': 'H', 'S': 'Q', 'T': 'F',
                        'U': 'V', 'V': 'S', 'W': 'Z', 'X': 'I', 'Y': 'J',
                        'Z': 'W'
                    }

                    ciphertext = ''
                    for char in plaintext:
                        if char.isalpha() and char.upper() in substitution:
                            if char.islower():
                                ciphertext += substitution[char.upper()].lower()
                            else:
                                ciphertext += substitution[char.upper()]
                        else:
                            ciphertext += char

                    return ciphertext

                plaintext = input("enter the message : ")
                encrypted_text = monoalphabetic_cipher_encrypt(plaintext)
                p("Encrypted text : " + encrypted_text)

            elif cypher == 4:
                def generate_playfair_matrix(key):
                    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
                    key = re.sub(r'[^A-Z]', '', key.upper())
                    key = key.replace("J", "I")
                    key = "".join(dict.fromkeys(key))
                    matrix = []
                    for char in key + alphabet:
                        if char not in matrix:
                            matrix.append(char)
                    return matrix

                def prepare_text(text):
                    text = re.sub(r'[^A-Z]', '', text.upper())
                    text = text.replace("J", "I")

                    prepared_text = ""
                    i = 0
                    while i < len(text):
                        prepared_text += text[i]
                        if i + 1 < len(text):
                            if text[i] == text[i + 1]:
                                prepared_text += "X"
                            prepared_text += text[i + 1]
                            i += 1
                        else:
                            prepared_text += "X"
                        i += 1

                    if len(prepared_text) % 2 != 0:
                        prepared_text += "X"

                    return prepared_text

                def encrypt(plaintext, key):
                    matrix = generate_playfair_matrix(key)
                    prepared_text = prepare_text(plaintext)

                    cipher_text = ""
                    i = 0
                    while i < len(prepared_text):
                        char1 = prepared_text[i]
                        char2 = prepared_text[i + 1]

                        row1, col1 = divmod(matrix.index(char1), 5)
                        row2, col2 = divmod(matrix.index(char2), 5)

                        if col1 == col2:
                            row1 = (row1 + 1) % 5
                            row2 = (row2 + 1) % 5

                        elif row1 == row2:
                            col1 = (col1 + 1) % 5
                            col2 = (col2 + 1) % 5

                        else:
                            col1, col2 = col2, col1

                        cipher_text += matrix[row1 * 5 + col1]
                        cipher_text += matrix[row2 * 5 + col2]

                        i += 2

                    return cipher_text

                key = input("Enter the key : ")
                plaintext = input("enter the message : ")

                cipher_text = encrypt(plaintext, key)
                p("Encrypted text : " + cipher_text)
            elif cypher == 99:
                return 0
        except ValueError:
            p('_________________________________')
            p("Please enter a valid choice (1, 2, 3, 4, or 99)")


def decryption():
    while True:
        try:
            p('_________________________________')
            cypher = int(input(color("【𝟭】Caesar\n【𝟮】Rotor Cipher\n【𝟯】monoalphabetic\n【𝟰】Play fair\n【99】Back  \nEnter your choice : ", 'cyan')))
            p('_________________________________')
            if cypher == 1:
                def decrypt_caesar(ciphertext, shift):
                    decrypted_text = ""
                    for char in ciphertext:
                        if char.isalpha():
                            ascii_offset = ord('A') if char.isupper() else ord('a')
                            decrypted_char = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                            decrypted_text += decrypted_char
                        else:
                            decrypted_text += char
                    return decrypted_text

                encrypted_text = input("enter the cypher text : ")
                shift = int(input("Enter shift : "))
                decrypted_text = decrypt_caesar(encrypted_text, shift)
                p("Decrypted text : " + decrypted_text)

            elif cypher == 2:
                class RotorCipher:
                    def __init__(self, rotor_settings):
                        self.rotor_settings = rotor_settings

                    def encrypt(self, plaintext):
                        ciphertext = ""
                        for char in plaintext:
                            if char.isalpha():
                                char = char.upper()
                                if char in self.rotor_settings:
                                    char = self.rotor_settings[char]
                            ciphertext += char
                        return ciphertext

                    def decrypt(self, ciphertext):
                        decrypted_text = ""
                        reverse_rotor_settings = {v: k for k, v in self.rotor_settings.items()}
                        for char in ciphertext:
                            if char.isalpha():
                                char = char.upper()
                                if char in reverse_rotor_settings:
                                    char = reverse_rotor_settings[char]
                            decrypted_text += char
                        return decrypted_text

                rotor_settings = {
                    'A': 'M', 'B': 'N', 'C': 'B', 'D': 'V', 'E': 'C', 'F': 'X',
                    'G': 'Z', 'H': 'A', 'I': 'S', 'J': 'D', 'K': 'F', 'L': 'G',
                    'M': 'H', 'N': 'J', 'O': 'K', 'P': 'L', 'Q': 'P', 'R': 'O',
                    'S': 'I', 'T': 'U', 'U': 'Y', 'V': 'T', 'W': 'R', 'X': 'E',
                    'Y': 'W', 'Z': 'Q'
                }

                cipher = RotorCipher(rotor_settings)

                ciphertext = input("Enter the ciphertext: ")
                plaintext = cipher.decrypt(ciphertext)

                p("Decrypted text : " + plaintext)

            elif cypher == 3:
                def monoalphabetic_cipher_decrypt(ciphertext):
                    substitution = {
                        'A': 'E', 'B': 'G', 'C': 'R', 'D': 'T', 'E': 'K',
                        'F': 'P', 'G': 'Y', 'H': 'O', 'I': 'L', 'J': 'X',
                        'K': 'A', 'L': 'M', 'M': 'N', 'N': 'C', 'O': 'U',
                        'P': 'B', 'Q': 'D', 'R': 'H', 'S': 'Q', 'T': 'F',
                        'U': 'V', 'V': 'S', 'W': 'Z', 'X': 'I', 'Y': 'J',
                        'Z': 'W'
                    }

                    decryption = {v: k for k, v in substitution.items()}

                    plaintext = ''
                    for char in ciphertext:
                        if char.isalpha() and char.upper() in decryption:
                            if char.islower():
                                plaintext += decryption[char.upper()].lower()
                            else:
                                plaintext += decryption[char.upper()]
                        else:
                            plaintext += char

                    return plaintext

                encrypted_text = input("enter the message : ")
                decrypted_text = monoalphabetic_cipher_decrypt(encrypted_text)
                p("Decrypted text : " + decrypted_text)

            elif cypher == 4:
                def generate_playfair_matrix(key):
                    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
                    key = re.sub(r'[^A-Z]', '', key.upper())
                    key = key.replace("J", "I")
                    key = "".join(dict.fromkeys(key))
                    matrix = []
                    for char in key + alphabet:
                        if char not in matrix:
                            matrix.append(char)
                    return matrix

                def decrypt(ciphertext, key):
                    matrix = generate_playfair_matrix(key)
                    plaintext = ""
                    i = 0
                    while i < len(ciphertext):
                        char1 = ciphertext[i]
                        char2 = ciphertext[i + 1]
                        row1, col1 = divmod(matrix.index(char1), 5)
                        row2, col2 = divmod(matrix.index(char2), 5)
                        if col1 == col2:
                            row1 = (row1 - 1) % 5
                            row2 = (row2 - 1) % 5
                        elif row1 == row2:
                            col1 = (col1 - 1) % 5
                            col2 = (col2 - 1) % 5
                        else:
                            col1, col2 = col2, col1
                        plaintext += matrix[row1 * 5 + col1]
                        plaintext += matrix[row2 * 5 + col2]
                        i += 2
                    p("Decrypted text : " + plaintext)

                cipher_text = input("Enter the ciphertext: ")
                key = input("Enter the key : ")
                decrypt(cipher_text, key)

            elif cypher == 99:
                return 0
            else:
                p("Enter a valid value!!")
        except ValueError:
            p('_________________________________')
            p("Please enter a valid choice (1, 2, 3, 4, or 99)")



def gradient_print(text):
    parts = len(text)
    for i, char in enumerate(text):
        ratio = i / (parts - 1)
        r = int(ratio * 255)
        g = 255
        b = int((1 - ratio) * 255)
        color = f"\033[38;2;{r};{g};{b}m"
        print(color + char, end='', flush=True)
        time.sleep(0.01)
    reset_color = Style.RESET_ALL
    print(reset_color)

def p(text):
    from colorama import init, Fore, Back, Style
    init()
    phosphor_green = Fore.GREEN
    sky_blue = Fore.BLUE
    text = text
    gradient_text = ''
    for i in range(len(text)):
        ratio = i / (len(text) - 1)
        r = int(255 - (255 * ratio))  # قيمة اللون الأحمر تنخفض
        g = int(200 + (55 * ratio))  # قيمة اللون الأخضر ترتفع
        b = int(255 * math.sin(ratio * math.pi / 2))
        color = f"\033[38;2;{r};{g};{b}m"
        gradient_text += color + text[i]
    reset_color = Style.RESET_ALL
    gradient_text += reset_color
    print(gradient_text)
def logo():
    logo_text = pyfiglet.figlet_format('d3F4LT', 'big')
    gradient_print(logo_text)


def main():
    logo()
    p("""Dedicated to encryption,decryption,and hash type 
    ╔═════════════════════════════════╗
    ║ ▶  Designer    :      Yuosuf    ║
    ║ ▶  Telegram    :      v9x_3     ║
    ║ ▶  Instagram   :      80.ea     ║
    ╚═════════════════════════════════╝
    """)
    while True:
        try:
            fun = int(input(color("【𝟭】encryption \n【𝟮】decryption \n【𝟯】hash \n【𝟰】Exit \nEnter your choice : ", 'cyan')))
            if fun == 1:
                encryption()
                p('_________________________________')
            elif fun == 2:
                decryption()
                p('_________________________________')
            elif fun == 3:
                while True:
                    hash_value = input("Enter the hash value: ")
                    hash_type = hash_types(hash_value)
                    p("Hash type: " + hash_type)
                    p('_________________________________')
                    z=input("Do you want to go back?(y/n)")
                    if z == 'y':
                        break
            elif fun == 4:
                break
            else :
                p('_________________________________')
                p("Please enter a valid choice (1, 2, 3, or 4)")
                p('_________________________________')
        except ValueError:
            p('_________________________________')
            p("Please enter a valid choice (1, 2, 3, or 4)")
            p('_________________________________')

main()

