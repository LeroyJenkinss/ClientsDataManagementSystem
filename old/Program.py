import os
import sqlite3

from ClientsDataManagementSystem.EncryptingDb import EncryptingDb
from ClientsDataManagementSystem.CreateUserAccount import CreateUserOrLogin
from ClientsDataManagementSystem.CreateUserAccount import LoginUser

class Program:

    # createuserorlogin = CreateUserOrLogin().tableEntries()
    login = LoginUser().login()

    encryptingdata = EncryptingDb().encrypt('aap', 2)
    print(encryptingdata)
    encryptingdata = EncryptingDb().encrypt('ccr', 24)
    print(encryptingdata)
    # Het decoden moet met 26 - steps
    # number of steps should be written to a file calles secret steps










