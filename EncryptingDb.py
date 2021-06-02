import kwargs as kwargs

from cryptography.fernet import Fernet


class EncryptingDb():

    key = ''
    def generate_key(self):
        """
        Generates a key and save it into a file
        """
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)

    def load_key(self):
        """
        Loads the key named `secret.key` from the current directory.
        """
        return open("secret.key", "rb").read()

    def encrypt_message(self,message):
        """
        Encrypts a message
        """
        key = self.load_key()
        encoded_message = message.encode()
        f = Fernet(key)
        encrypted_message = f.encrypt(encoded_message)

        print(encrypted_message)

    def decrypt_message(self,encrypted_message):
        """
        Decrypts an encrypted message
        """
        key = self.load_key()
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_message)

        print(decrypted_message.decode())