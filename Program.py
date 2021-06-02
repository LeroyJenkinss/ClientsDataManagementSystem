import os
import sqlite3

from ClientsDataManagementSystem.EncryptingDb import EncryptingDb
from ClientsDataManagementSystem.CreateUserAccount import CreateUserOrLogin

class Program:

    # createuserorlogin = CreateUserOrLogin().tableEntries()


    encryptingdata = EncryptingDb().encrypt('aap', 2)
    print(encryptingdata)
    encryptingdata = EncryptingDb().encrypt('ccr', 24)
    print(encryptingdata)
    # Het decoden moet met 26 - steps











