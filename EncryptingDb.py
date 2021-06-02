import kwargs as kwargs

from cryptography.fernet import Fernet


class EncryptingDb():

    def encrypt(self,text, s):
        result = ""

        # traverse text
        for i in range(len(text)):
            char = text[i]

            # Encrypt uppercase characters
            if (char.isupper()):
                result += chr((ord(char) + s - 65) % 26 + 65)

            # Encrypt lowercase characters
            else:
                result += chr((ord(char) + s - 97) % 26 + 97)

        return result





    print()