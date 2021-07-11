import sqlite3
from ui import *
from termcolor import colored
import EncryptingDb
from zipfile import ZipFile
from datetime import datetime
from tabulate import tabulate
import logging

# GLobal Variables
# --------------------------------------------------------------------
max_input_try = 3
company_db_name = 'mycompany.db'
client_tb_name = 'client'
users_tb_name = 'users'
encryption = EncryptingDb.EncryptingDb()
now = datetime.now()
lowercase_letters = [chr(code) for code in range(ord('a'), ord('z') + 1)]
uppercase_letters = [chr(code) for code in range(ord('A'), ord('Z') + 1)]
digits = [chr(code) for code in range(ord('0'), ord('9') + 1)]


# uginput class
class uginput:
    def __init__(self, domain_type: str, min_len=None, max_len=None, range=None):

        self.min_len = min_len
        self.max_len = max_len
        self.range = range
        self.domain_type = domain_type

    def _isValidUsername(self):
        if self.value is None:
            logging.logging('None', 'checking_username', 'username has null value', '1')
            return False
        symbols_premitted = ['!', '.', '_']
        white_list = []
        white_list.extend(lowercase_letters)
        white_list.extend(uppercase_letters)
        white_list.extend(digits)
        white_list.extend(symbols_premitted)

        print(self.value[0])
        if self.value:
            valid = [
                self._length(self.min_len, self.max_len),
                self._checkFirstChar(self.value[0],lowercase_letters,uppercase_letters),
                self._checkwhitelist(white_list)]
            return all(valid)
        else:
            logging.logging(self.value, 'checking_username', 'username is not valid', '1')
            return False

    def _check(self):
        symPremitted = ['~', '!', '@', '#', '$', '%', '^', '&', '*', '_', '-', '+', '=', '`', '|', '\\', '(', ')',
                             '{', '}', '[', ':', ';', "'", '<', '>', ',', '.', '?', '/']
        if any(x.isupper() for x in self.value) and (any(x.islower() for x in self.value)) and (any(x for x in digits)) and (any(x for x in symPremitted)):
            return True
        return False
        print('hellloooooo')

    def _checkwhitelist(self, white_list):
        for a in self.value:
            if a not in white_list:
                return False
        return True

    def input(self, question):
        self.value = input(question)


    def _length(self, min=0, max=64):
        name = self.value
        if min <= len(name) <= max:
            return True
        return False

    def _checkFirstChar(self,char2Check,lowerLetters,upperLetters):
        if char2Check  in lowerLetters:
            return True
        elif char2Check in upperLetters:
            return  True
        else:
            return False

    def _isValidPassword(self):
        if self.value is None:
            logging.logging('None', 'checking_password', 'password has null value', '1')
            return False
        symbols_premitted = ['~', '!', '@', '#', '$', '%', '^', '&', '*', '_', '-', '+', '=', '`', '|', '\\', '(', ')',
                             '{', '}', '[', ':', ';', "'", '<', '>', ',', '.', '?', '/']
        white_list = []
        white_list.extend(lowercase_letters)
        white_list.extend(uppercase_letters)
        white_list.extend(digits)
        white_list.extend(symbols_premitted)

        if self.value:
            valid = [
                self._length(self.min_len, self.max_len),
                self._check(),
                self._checkwhitelist(white_list)]


            return all(valid)
        else:
            logging.logging(self.value, 'checking_username', 'username is not valid', '1')
            return False

    def isValid(self):
        domain_func = {
            'username': self._isValidUsername,
            'password': self._isValidPassword,
            # 'email': self._isValidEmail
        }

        methodCall = (domain_func[self.domain_type]())
        return methodCall


# User
# --------------------------------------------------------------------
class user:
    def __init__(self, user_data):
        self.username = user_data[0]
        self.password = user_data[1]
        self.name = user_data[2]
        self.admin = user_data[3]
        self.advisor = user_data[4]


# Database
# --------------------------------------------------------------------
class db:
    def __init__(self, db_name, client_table_name, users_table_name):
        self.db_name = db_name
        self.client_table_name = client_table_name
        self.users_table_name = users_table_name

        self.loggedin = 0
        self.loggedin_user = None
        self.admin_is_loggedin = 0

        self.reset()

    def reset(self):
        self.conn = sqlite3.connect(self.db_name)
        self.cur = self.conn.cursor()

        # create client table if it does not exist
        tb_create = '''CREATE TABLE client (fullname CHAR(30) ,StreetAddress varchar(40),HouseNumber varchar(10),ZipCode varchar(6),City varchar(40),EmailAddress varchar(50),MobilePhone varchar(30))'''
        try:
            self.cur.execute(tb_create)
            # add sample records to the db manually
            client1 = F"INSERT INTO client (fullname, StreetAddress, HouseNumber, ZipCode, City, EmailAddress, MobilePhone) VALUES ('{encryption.encrypt('Lili Anderson')}', '{encryption.encrypt('teststraat')}', '{encryption.encrypt('21B')}', '{encryption.encrypt('3114XE')}', '{encryption.encrypt('staddam')}', '{encryption.encrypt('test@test.nl')}', '{encryption.encrypt('+31-6-12345678')}')"
            self.cur.execute(client1)
            client2 = F"INSERT INTO client (fullname, StreetAddress, HouseNumber, ZipCode, City, EmailAddress, MobilePhone) VALUES ('{encryption.encrypt('Anne Banwarth')}', '{encryption.encrypt('teststrfggaat')}', '{encryption.encrypt('25B')}', '{encryption.encrypt('3134XE')}', '{encryption.encrypt('staddsaddam')}', '{encryption.encrypt('tesdadasst@test.nl')}', '{encryption.encrypt('+31-6-12345678')}')"
            self.cur.execute(client2)
            self.conn.commit()
        except:
            None

        # create user table if it does not exist
        tb_create = "CREATE TABLE users (username TEXT, password TEXT, fullname TEXT, admin varchar);"
        try:
            self.cur.execute(tb_create)
            # add sample records to the db manually
            self.cur.execute(
                F"INSERT INTO users (username, password, fullname, admin) VALUES ('{encryption.encrypt('superadmin')}', '{encryption.encrypt('Admin!23')}', '{encryption.encrypt('Bob SuperAdmin')}', {encryption.encrypt('2')})")
            self.cur.execute(
                F"INSERT INTO users (username, password, fullname, admin) VALUES ('{encryption.encrypt('bob.l')}', '{encryption.encrypt('B0b!23')}', '{encryption.encrypt('Bob Larson')}', {encryption.encrypt('1')})")
            self.cur.execute(
                F"INSERT INTO users (username, password, fullname, admin) VALUES ('{encryption.encrypt('ivy_russel')}', '{encryption.encrypt('ivy@R123')}' , '{encryption.encrypt('Ivy Russel')}', {encryption.encrypt('0')})")
            self.conn.commit()
        except:
            None

        # create logging table if it doesnt excist
        # sqlite3 doesnt have datetime or boolean(0 = false, 1 = true), date and time are strings and boolean is iteger
        tb_create = "CREATE TABLE logging (username TEXT, date TEXT, time TEXT, description_of_activity TEXT, additionalInfo TEXT, supicious varchar)"
        try:
            self.cur.execute(tb_create)
            self.cur.execute(
                F"INSERT INTO logging (username, date, time, description_of_activity, additionalInfo, supicious) VALUES ('{encryption.encrypt('Billy')}', '{encryption.encrypt('30-10-1979')}', '{encryption.encrypt('19:28:00')}', '{encryption.encrypt('log on')}', '{encryption.encrypt('Hassan loggedin')}', {encryption.encrypt('0')})")
            self.conn.commit()
        except:
            None

    def login(self):

        username = uginput('username', 5, 12)
        username.input('please enter username:')
        if not username.isValid():
            print('username or password is incorrect')
            return

        password = uginput('password', 8, 30)
        password.input('please enter password:')
        if not password.isValid():
            print('username or password is incorrect')
            return

        # string concatenation
        # sql_statement = f"SELECT * from users WHERE username='{username}' AND password='{password}'"
        sql_statement = f'SELECT * from users WHERE username="{encryption.encrypt(username.value)}" AND password="{encryption.encrypt(password.value)}"'

        self.cur.execute(sql_statement)

        loggedin_user = self.cur.fetchone()
        if not loggedin_user:  # An empty result evaluates to False.
            print("Login failed")

        else:
            self.loggedin = 1
            self.loggedin_user = encryption.decrypt(username.value)
            self.admin_is_loggedin = encryption.decrypt(loggedin_user[3])
            user_type = 'Admin' if self.admin_is_loggedin == 1 else 'Not Admin'
            if self.admin_is_loggedin == '0':
                user_type = 'Advisor'
                print('\n\n\n\nWelcome')
                heading = '▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄' + '\n' + \
                          '▍ ' + '\n' + \
                          '▍ Username: ' + colored(self.loggedin_user, 'red') + '\n' + \
                          '▍ ' + '\n' + \
                          '▍ User type: ' + colored(user_type, 'red') + '\n' + \
                          '▍ ' + '\n' + \
                          '▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀' + '\n' + \
                          'User Menu'

                db_interface = user_interface(heading, db_menu_advisor)
                db_interface.run()
                del db_interface
            elif self.admin_is_loggedin == '1':
                user_type = 'System Administrator'
                print('\n\n\n\nWelcome')
                heading = '▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄' + '\n' + \
                          '▍ ' + '\n' + \
                          '▍ Username: ' + colored(self.loggedin_user, 'red') + '\n' + \
                          '▍ ' + '\n' + \
                          '▍ User type: ' + colored(user_type, 'red') + '\n' + \
                          '▍ ' + '\n' + \
                          '▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀' + '\n' + \
                          'User Menu'

                db_interface = user_interface(heading, db_menu_system_admin)
                db_interface.run()
                del db_interface
            elif self.admin_is_loggedin == '2':
                user_type = 'Super Administrator'
                print('\n\n\n\nWelcome')
                heading = '▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄' + '\n' + \
                          '▍ ' + '\n' + \
                          '▍ Username: ' + colored(self.loggedin_user, 'red') + '\n' + \
                          '▍ ' + '\n' + \
                          '▍ User type: ' + colored(user_type, 'red') + '\n' + \
                          '▍ ' + '\n' + \
                          '▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀' + '\n' + \
                          'User Menu'

                db_interface = user_interface(heading, db_menu_super_admin)
                db_interface.run()
                del db_interface

    def show_all_clients(self):
        sql_statement = 'SELECT * from client'
        self.cur.execute(sql_statement)
        clients = self.cur.fetchall()
        decryptedList = encryption.decryptNestedTupleToNestedList(clients)
        print(tabulate(decryptedList,
                       headers=['fullname', 'streetaddress', 'housenumber', 'zipcode', 'city', 'email address',
                                'mobile phone number']))

    def search_client(self):
        self.not_implemented(self.show_all_clients)

    def show_all_users(self):
        self.not_implemented(self.show_all_users)

    def add_new_client(self):
        fullname = input("please enter fullname: ")
        StreetAddress = input("please enter StreetAddress: ")
        HouseNumber = input("please enter HouseNumber: ")
        ZipCode = input("please enter ZipCode: ")
        City = input("please enter City: ")
        EmailAddress = input("please enter EmailAddress: ")
        MobilePhone = input("please enter MobilePhone +31-6-: ")
        client1 = F"INSERT INTO client (fullname, StreetAddress, HouseNumber, ZipCode, City, EmailAddress, MobilePhone) VALUES ('{encryption.encrypt(fullname)}', '{encryption.encrypt(StreetAddress)}', '{encryption.encrypt(HouseNumber)}', '{encryption.encrypt(ZipCode)}', '{encryption.encrypt(City)}', '{encryption.encrypt(EmailAddress)}', '{encryption.encrypt('+31-6-' + MobilePhone)}')"
        self.cur.execute(client1)

    def make_a_user_admin(self):
        self.not_implemented(self.make_a_user_admin)

    def delete_client(self):
        self.not_implemented(self.delete_client)

    def modify_client(self):
        self.not_implemented(self.delete_client)

    def delete_user(self):
        self.not_implemented(self.delete_user)

    def change_password(self):
        self.not_implemented(self.change_password)

    def backup(self):
        # create a ZipFile object
        zipObj = ZipFile(f"systembackuo{now.strftime('%d-%m-%Y-%H-%M')}.zip", 'w')
        # Add multiple files to the zip
        zipObj.write('mycompany.db')
        # close the Zip File
        zipObj.close()

    def add_new_advisor(self):
        self.not_implemented(self.add_new_advisor)

    def modify_advisor(self):
        self.not_implemented(self.modify_advisor)

    def delete_advisor(self):
        self.not_implemented(self.delete_advisor)

    def reset_advisor_password(self):
        self.not_implemented(self.reset_advisor_password)

    def add_new_admin(self):
        self.not_implemented(self.add_new_admin)

    def modify_admin(self):
        self.not_implemented(self.modify_admin)

    def delete_admin(self):
        self.not_implemented(self.delete_admin)

    def reset_admin_password(self):
        self.not_implemented(self.reset_admin_password)

    def read_logs(self):
        sql_statement = 'SELECT * from logging'
        self.cur.execute(sql_statement)
        log = self.cur.fetchall()
        decryptedList = encryption.decryptNestedTupleToNestedList(log)
        print(tabulate(decryptedList,
                       headers=['username', 'date', 'time', 'description_of_activity', 'additionalInfo', 'supicious']))

    def logout(self):
        self.loggedin = 0
        self.loggedin_user = None
        self.admin_is_loggedin = 0

    def close(self):
        self.conn.close()

    def not_implemented(self, func):
        print(func.__name__ + ' method is Not implemented')

    def see_loggingFile(self):
        return

    def insertLoggingInDB(self, username, date, time, description_of_activity, additionalInfo, supicious):
        sql_statement = f"INSERT INTO logging (username, date, time, description_of_activity, additionalInfo, supicious) VALUES (date, time, description_of_activity, additionalInfo, supicious)"
        self.cur.execute(sql_statement)

    def escape_sql_meta(sql_query):
        pass


client = db(company_db_name, client_tb_name, users_tb_name)
main_menu = [[1, 'login', client.login], [0, 'Exit', client.close]]
db_menu_advisor = [[1, 'change password', client.change_password], [2, 'add new client', client.add_new_client], \
                   [3, 'show all clients', client.show_all_clients], [4, 'search for client', client.search_client], \
                   [5, 'modify a client', client.modify_client], [0, 'logout', client.logout]]

db_menu_system_admin = [[1, 'change password', client.change_password], [2, 'show all users', client.show_all_users], \
                        [3, 'add new client', client.add_new_client], [4, 'add new advisor', client.add_new_advisor], \
                        [5, 'delete a client', client.delete_client], [6, 'delete a user', client.delete_user], \
                        [7, 'modify advisor', client.modify_advisor], [8, 'delete a advisor', client.delete_advisor], \
                        [9, 'reset advisor password', client.reset_advisor_password],
                        [10, 'read logs', client.read_logs], \
                        [11, 'modify a client', client.modify_client], [12, 'delete client', client.delete_client], \
                        [13, 'search for client', client.search_client], \
                        [14, 'make backup', client.backup], [0, 'logout', client.logout]]

db_menu_super_admin = [[1, 'show all clients', client.show_all_clients], [2, 'show all users', client.show_all_users], \
                       [3, 'add new client', client.add_new_client], [4, 'add new advisor', client.add_new_advisor], \
                       [5, 'delete a client', client.delete_client], [6, 'delete a user', client.delete_user], \
                       [7, 'modify advisor', client.modify_advisor], [8, 'delete a advisor', client.delete_advisor], \
                       [9, 'reset advisor password', client.reset_advisor_password],
                       [10, 'read logs', client.read_logs], \
                       [11, 'modify a client', client.modify_client], [12, 'delete client', client.delete_client], \
                       [13, 'search for client', client.search_client], [14, 'add new admin', client.add_new_admin], \
                       [15, 'modify admin', client.modify_admin], [16, 'delete a admin', client.delete_admin], \
                       [17, 'reset admin password', client.reset_admin_password],
                       [18, 'make backup', client.backup], [0, 'logout', client.logout]]
