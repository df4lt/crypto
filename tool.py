import hashlib

colors = {
    "red": "\033[1;31m",
    "green": "\033[1;32m",
    "yellow": "\033[1;33m",
    "blue": "\033[1;34m",
    "purple": "\033[1;35m",
    "cyan": "\033[1;36m",
    "white": "\033[1;37m",
    "dark_gray": "\033[1;90m",
    "dark_red": "\033[0;31m",
    "dark_green": "\033[0;32m",
    "dark_yellow": "\033[0;33m",
    "dark_blue": "\033[0;34m",
    "dark_purple": "\033[0;35m",
    "dark_cyan": "\033[0;36m",
    "dark_gray": "\033[1;90m",
    "gray": "\033[0;37m",
    "light_red": "\033[1;31m",
    "light_green": "\033[1;32m",
    "light_yellow": "\033[1;33m",
    "light_blue": "\033[1;34m",
    "light_purple": "\033[1;35m",
    "light_cyan": "\033[1;36m",
    "light_gray": "\033[1;37m"
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
    cypher = int(input("1.Caesar\n2.Rotor Cipher\n3.monoalphabetic\n4.Play fair \n"))
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
        print("Encrypted text :", encrypted_text)
    elif  cypher == 2:
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
            'A': 'M',
            'B': 'N',
            'C': 'B',
            'D': 'V',
            'E': 'C',
            'F': 'X',
            'G': 'Z',
            'H': 'A',
            'I': 'S',
            'J': 'D',
            'K': 'F',
            'L': 'G',
            'M': 'H',
            'N': 'J',
            'O': 'K',
            'P': 'L',
            'Q': 'P',
            'R': 'O',
            'S': 'I',
            'T': 'U',
            'U': 'Y',
            'V': 'T',
            'W': 'R',
            'X': 'E',
            'Y': 'W',
            'Z': 'Q'
        }

            cipher = RotorCipher(rotor_settings)

            plaintext = input ("enter the message : ")

            ciphertext = cipher.encrypt(plaintext)
            print("Encrypted text : ", ciphertext)

    elif cypher == 3 :
        def monoalphabetic_cipher_encrypt(plaintext):
            substitution = {
                'A': 'E',
                'B': 'G',
                'C': 'R',
                'D': 'T',
                'E': 'K',
                'F': 'P',
                'G': 'Y',
                'H': 'O',
                'I': 'L',
                'J': 'X',
                'K': 'A',
                'L': 'M',
                'M': 'N',
                'N': 'C',
                'O': 'U',
                'P': 'B',
                'Q': 'D',
                'R': 'H',
                'S': 'Q',
                'T': 'F',
                'U': 'V',
                'V': 'S',
                'W': 'Z',
                'X': 'I',
                'Y': 'J',
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


        plaintext = input ("enter the message : ")
        encrypted_text = monoalphabetic_cipher_encrypt(plaintext)
        print("encrypted text : ", encrypted_text)
    elif cypher == 4 :
        import re


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

            return plaintext


        key = input("Enter the key : ")
        plaintext = input("enter the message : ")

        
        cipher_text = encrypt(plaintext, key)
        print("Encrypted text :", cipher_text)


def decryption ():
    cypher = int(input("1.Caesar\n2.Rotor Cipher\n3.monoalphabetic\n4.Play fair  \n"))
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
        encrypted_text = input ("enter the cypher text : ")
        shift =int (input ("Enter shift : "))
        decrypted_text = decrypt_caesar(encrypted_text, shift)
        print("Decrypted text:", decrypted_text)
    elif cypher  == 2:
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
    
        print("Decrypted text:", plaintext)
    elif cypher == 3 :
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

        encrypted_text = input ("enter the message : ")
        decrypted_text = monoalphabetic_cipher_decrypt(encrypted_text)
        print("Decrypted text:", decrypted_text)

    elif cypher == 4 :
        import re

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
            return plaintext
        cipher_text=input("enter cypher text : ")
        key = input("enter the key : ") 
        decrypted_text = decrypt(cipher_text, key)
        print("Decrypted text:", decrypted_text)


def main():

    fun=int(input(color("what do you need  \n1)encryption \n2)decryption \n3)hash \n4)Exit \n",'dark_purple')))
    while True :
        if fun == 1 :
            encryption() 
        elif fun == 2 :
              decryption()
        elif fun == 3 :
            hash_value = input("Enter the hash value: ")
            hash_type = hash_types(hash_value)
            print("Hash type:", hash_type)
        elif fun == 4:
            break
        fun=int(input("what do you need  \n1)encryption \n2)decryption \n3)hash \n4)Exit \n"))
main()