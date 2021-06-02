import os
import sqlite3

from ClientsDataManagementSystem.EncryptingDb import EncryptingDb
from ClientsDataManagementSystem.CreateUserAccount import CreateUserOrLogin

class Program:

    # createuserorlogin = CreateUserOrLogin().tableEntries()
    if os.path.isfile('secret.key'):
        print('key already present')
    else:
        encryptingdata = EncryptingDb().generate_key()

    










