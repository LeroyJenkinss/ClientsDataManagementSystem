

class EncryptingDb:

    def encrypt(self,text, key = 3):
        encrypted = ""

        for c in text:

            if c.isupper():  # check if it's an uppercase character

                c_index = ord(c) - ord('A')

                # shift the current character by key positions
                c_shifted = (c_index + key) % 26 + ord('A')

                c_new = chr(c_shifted)

                encrypted += c_new

            elif c.islower():  # check if its a lowecase character

                # subtract the unicode of 'a' to get index in [0-25) range
                c_index = ord(c) - ord('a')

                c_shifted = (c_index + key) % 26 + ord('a')

                c_new = chr(c_shifted)

                encrypted += c_new

            elif c.isdigit():

                # if it's a number,shift its actual value
                c_new = (int(c) + key) % 10

                encrypted += str(c_new)

            else:

                # if its neither alphabetical nor a number, just leave it like that
                encrypted += c

        return encrypted

    def decrypt(self,text, key = 3):
        decrypted = ""

        for c in text:

            if c.isupper():

                c_index = ord(c) - ord('A')

                # shift the current character to left by key positions to get its original position
                c_og_pos = (c_index - key) % 26 + ord('A')

                c_og = chr(c_og_pos)

                decrypted += c_og

            elif c.islower():

                c_index = ord(c) - ord('a')

                c_og_pos = (c_index - key) % 26 + ord('a')

                c_og = chr(c_og_pos)

                decrypted += c_og

            elif c.isdigit():

                # if it's a number,shift its actual value
                c_og = (int(c) - key) % 10

                decrypted += str(c_og)

            else:

                # if its neither alphabetical nor a number, just leave it like that
                decrypted += c

        return decrypted

    def decryptTupleToList(self, tupple):
        newList = []
        for t in tupple:
            newList.append(self.decrypt(t))

        return newList

        # print(tupple)
        # print(" ".join(tupple))
        # tuppleString = " ".join(tupple)
        # print(tuppleString)
        # decryptedString = self.decrypt(tuppleString)
        # newList = list(decryptedString.split(" "))
        # return newList

    def decryptNestedTupleToNestedList(self, tupple):
        newList = []
        for t in tupple:
            newList.append(self.decryptTupleToList(t))

        return newList






    print()