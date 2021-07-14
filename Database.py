import re
import sqlite3
from sqlite3.dbapi2 import Connection

from ui import *
from termcolor import colored
import EncryptingDb
from zipfile import ZipFile
from tabulate import tabulate
from datetime import datetime, date
from time import localtime, strftime

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
symbols_premitted = ['!', '@', '#', '$', '^', '_', '+', '`', '|',
                     '{', '}', ':', '<', '>', '?', '/']
blacklist = ['-', '=', '(', ')', '[', "'", ';', ',', '.', '/' '\\', ']']
cities = [
    [1, 'Ankara'], [2, 'Marakesh'], [3, 'Samsun'], [4, 'Sivas'], [5, 'Tehran'], [6, 'Nijkerk'], [7, 'Nador'],
    [8, 'Istanbul'], [9, 'Gaza'], [10, 'Mashhad']
]


class logging():

    def __init__(self, db, username, description_of_activity, additionalinfo, suspicious):
        self.username = encryption.encrypt(username)
        self.date = encryption.encrypt(now.strftime('%d-%m-%Y'))
        self.time = encryption.encrypt(strftime("%H:%M:%S", localtime()))
        self.description_of_activity = encryption.encrypt(description_of_activity)
        self.additionalinfo = encryption.encrypt(additionalinfo)
        self.suspicious = encryption.encrypt(f'{suspicious}')
        self.read = encryption.encrypt(f'{0}')
        try:
            client.cur.execute(
                F"INSERT INTO logging (username, date, time, description_of_activity, additionalinfo, supicious, read) VALUES ('{self.username}','{self.date}','{self.time}','{self.description_of_activity}','{self.additionalinfo}','{self.suspicious}','{self.read}')")
        except:
            client.cur.execute(
                F"INSERT INTO logging (username, date, time, description_of_activity, additionalinfo, supicious, read) VALUES ('{self.username}','{self.date}','{self.time}','{self.description_of_activity}','{encryption.encrypt('Meta characters or unrecognized token inside')}','{encryption.encrypt('1')}','{self.read}')")
        client.conn.commit()


# uginput class
class uginput:
    def __init__(self, domain_type: str, min_len=None, max_len=None, range=None):

        self.min_len = min_len
        self.max_len = max_len
        self.range = range
        self.domain_type = domain_type

    def _isHouseNumberValid(self):
        if self.value is None:
            if client.user.username is None:
                logging(db, 'not logged in', f'checking_{self.domain_type}', f'{self.domain_type} has null value',
                        '1')
            else:
                logging(db, client.user.username, f'checking_{self.domain_type}', f'{self.domain_type} has null value',
                        '1')
            return False

        white_list = []
        white_list.extend(lowercase_letters)
        white_list.extend(uppercase_letters)
        white_list.extend(digits)

        if self.value:
            valid = [
                self._checkwhitelist(white_list)]
            if all(valid):
                return True
            else:
                if client.user.username is None:
                    logging(db, 'not logged in', f'checking_{self.domain_type}',
                            f'{self.domain_type} is not valid value: {self.value}', '1')
                else:
                    logging(db, client.user.username, f'checking_{self.domain_type}',
                            f'{self.domain_type} is not valid value: {self.value}', '1')
                return False

    def _isValidUsername(self):
        if self.value is None:
            if client.user.username is None:
                logging(db, 'not logged in', f'checking_{self.domain_type}', f'{self.domain_type} has null value',
                        '1')
            else:
                logging(db, client.user.username, f'checking_{self.domain_type}', f'{self.domain_type} has null value',
                        '1')
            return False

        symbols_premitted = ['!', '.', '_', '\'']
        white_list = []
        white_list.extend(lowercase_letters)
        white_list.extend(uppercase_letters)
        white_list.extend(digits)
        white_list.extend(symbols_premitted)

        if self.value:
            valid = [
                self._length(self.min_len, self.max_len),
                self._checkFirstChar(str(self.value[0]), lowercase_letters, uppercase_letters),
                self._checkwhitelist(white_list)]
            if all(valid):
                return True
            else:
                if client.user.username is None:
                    logging(db, 'not logged in', f'checking_{self.domain_type}',
                            f'{self.domain_type} is not valid value: {self.value}', '1')
                else:
                    logging(db, client.user.username, f'checking_{self.domain_type}',
                            f'{self.domain_type} is not valid value: {self.value}', '1')
                return False

    def _check(self):
        symPremitted = ['~', '!', '@', '#', '$', '%', '^', '&', '*', '_', '+', '`', '|',
                        '{', '}', ':', '<', '>', '?', ]
        if any(x.isupper() for x in self.value) and (any(x.islower() for x in self.value)) and (
                any(x for x in digits)) and (any(x for x in symPremitted)):
            return True
        logging(db, self.value, 'check_if_1capital_1lowerCase_1digit_1specialChar_is_present',
                'username is not valid', '1')
        return False

    def _checkemail(self):
        if self.value is None:
            logging(db, client.user.username, f'checking_{self.domain_type}',
                    f'Is empty',
                    '1')
            return  False
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

        if re.match(regex, self.value):
            return True
        return False

    def _checkZip(self):
        if self.value is None:
            logging(db, client.user.username, f'checking_{self.domain_type}',
                    f'Is empty',
                    '1')
            return False
        numbers = ['1','2','3','4','5','6','7','8','9']
        count = 0
        if self.value[0] in numbers:
            while count < 4:
                if self.value[count] not in digits:
                    return False
                count += 1
            while count < 6:
                if self.value[count] not in lowercase_letters and self.value[count] not in uppercase_letters:
                    return  False
                count += 1
        else:
            return False
        return True

    def _checktelephonenumber(self):
        if self.value is None:
            logging(db, client.user.username, f'checking_{self.domain_type}',
                    f'Is empty',
                    '1')
            return  False


        regex = r"^[0-9]{8}"

        if re.match(regex, self.value):
            return True
        logging(db, client.user.username, f'checking_{self.domain_type}',
                f'{self.value} is not a valid phonenumber',
                '1')
        return False

    def _checkwhitelist(self, white_list):
        for a in self.value:
            if a not in white_list:
                if client.user.username is None:
                    logging(db, 'not logged in', f'checking_all_chars_in_whitelist_{self.domain_type}',
                            f'{a} is not in the whitelist value: {self.value}',
                            '1')
                else:
                    logging(db, client.user.username, f'checking_all_chars_in_whitelist_{self.domain_type}',
                            f'{a} is not in the whitelist value: {self.value}',
                            '1')
                return False
        return True

    def intinput(self, question):
        self.value = int(input(question))

    def input(self, question):
        self.value = input(question)
    
    def _length(self, min=0, max=64):
        name = self.value
        if min <= len(name) <= max:
            return True
        if client.user.username is None:
            logging(db, 'not logged in', f'checking_min&max_length_{self.domain_type}', f'{self.value} is too short or too long',
                    '1')
        else:
            logging(db, client.user.username, f'checking_min&max_length_{self.domain_type}',
                    f'{self.value} is too short or too long', '1')
        return False

    def _checkFirstChar(self, char2Check, lowerLetters, upperLetters):
        if char2Check in lowerLetters:
            return True
        elif char2Check in upperLetters:
            return True
        else:
            if client.user.username is None:
                logging(db, 'not logged in', f'checking_{self.domain_type}', f'{self.value} is not valid',
                        '1')
            else:
                logging(db, client.user.username, f'checking_{self.domain_type}',
                        f'{self.value} is not valid', '1')
            return False

    def _isValidZipcode(self):
        if self.value is None:
            logging(db, client.user.username, 'checking_zipcode', 'zipcode has null value', '1')
            return False
        white_list = []
        white_list.extend(lowercase_letters)
        white_list.extend(uppercase_letters)
        white_list.extend(digits)

        if self.value:
            valid = [
                self._length(self.min_len, self.max_len),
                self._checkZip(),
                self._checkwhitelist(white_list)]
            if all(valid):
                return True
            else:
                if client.user.username is None:
                    logging(db, 'not logged in', f'checking_{self.domain_type}', f'{self.value} is not valid',
                            '1')
                else:
                    logging(db, client.user.username, f'checking_{self.domain_type}',
                            f'{self.value} is not valid', '1')
                return False



    def _isValidTelephonenumber(self):
        if self.value is None:
            logging(db, client.user.username, 'checking_telephonenumber', 'telephonenumber has null value', '1')
            return False
        white_list = []
        white_list.extend(digits)

        if self.value:
            valid = [
                self._length(self.min_len, self.max_len),
                self._checktelephonenumber(),
                self._checkwhitelist(white_list)]
            if all(valid):
                return True
            else:
                logging(db, client.user.username, 'checking_username', 'username is not valid', '1')
                return False

    def _inrange(self):
        if self.value is None:
            if client.user.username is None:
                logging(db, 'not logged in', f'checking_{self.domain_type}', f'{self.domain_type} has null value',
                        '1')
            else:
                logging(db, client.user.username, f'checking_{self.domain_type}', f'{self.domain_type} has null value', '1')
            return False
        for x in self.range:
            if x == self.value:
                return True
        if client.user.username is None:
            logging(db, 'not logged in', self.domain_type, 'Is not in range', '1')
        else:
            logging(db, client.user.username, self.domain_type, 'Is not in range', '1')
        return False

    def _isValidPassword(self):
        if self.value is None:
            if client.user.username is None:
                logging(db, 'not logged in', f'checking_{self.domain_type}', f'{self.domain_type} has null value',
                        '1')
            else:
                logging(db, client.user.username, f'checking_{self.domain_type}', f'{self.domain_type} has null value', '1')
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
            if all(valid):
                return True
            else:
                if client.user.username is None:
                    logging(db, 'not logged in', f'checking_{self.domain_type}',
                            f'{self.domain_type} is not valid', '1')
                else:
                    logging(db, client.user.username, f'checking_{self.domain_type}', f'{self.domain_type} is not valid value: {self.value}', '1')
                return False


    def isValid(self):
        domain_func = {
            'newpassword': self._isValidPassword,

            'oldpassword': self._isValidPassword,
            'housenumber': self._isHouseNumberValid,
            'streetadress': self._isValidUsername,
            'range': self._inrange,
            'adminname': self._isValidUsername,
            'advisorname': self._isValidUsername,
            'oldusername': self._isValidUsername,
            'fullname': self._isValidFullname,
            'username': self._isValidUsername,
            'password': self._isValidPassword,
            'email': self._isValidEmail,
            "zipcode": self._isValidZipcode,
            "telephonenumber": self._isValidTelephonenumber
        }

        methodCall = (domain_func[self.domain_type]())
        return methodCall

    def _isValidEmail(self):
        if self.value is None:
            logging(db, client.user.username, f'checking_{self.domain_type}', f'{self.domain_type} has null value', '1')
            return False

        symbols_premitted = ['~', '!', '@', '#', '$', '%', '^', '&', '*', '_', '-', '+', '=', '`', '|', '(', ')',
                             '{', '}', ';', "'", ',', '.', '?', '/']
        white_list = []
        white_list.extend(lowercase_letters)
        white_list.extend(uppercase_letters)
        white_list.extend(digits)
        white_list.extend(symbols_premitted)

        if self.value:
            valid = [
                self._length(self.min_len, self.max_len),
                self._checkemail(),
                self._checkwhitelist(white_list)]
            if all(valid):
                return True
            else:
                logging(db, client.user.username, f'checking_{self.domain_type}', f'{self.domain_type} is not valid', '1')
                return False

    def _isValidFullname(self):
        if self.value is None:
            logging(db, client.user.username, self.domain_type, 'fullname has null value', '1')
            return False

        symbols_premitted = ['.', '_', ' ']
        white_list = []
        white_list.extend(lowercase_letters)
        white_list.extend(uppercase_letters)
        white_list.extend(symbols_premitted)

        if self.value:
            valid = [
                self._length(self.min_len, self.max_len),
                self._checkFirstChar(str(self.value[0]), lowercase_letters, uppercase_letters),
                self._checkwhitelist(white_list)]
            if all(valid):
                return True
            else:
                logging(db, client.user.username, 'checking_fullname', 'fullname is not valid', '1')
                return False
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
    conn: Connection

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
            self.conn.commit()
        except:
            None

        # create user table if it does not exist
        tb_create = "CREATE TABLE users (username TEXT, password TEXT, fullname TEXT, admin varchar, attempts varchar, registerdDate varchar);"
        try:
            self.cur.execute(tb_create)
            # add Superadmin record to the db manually
            self.cur.execute(
                F"INSERT INTO users (username, password, fullname, admin, attempts, registerdDate) VALUES ('{encryption.encrypt('superadmin')}', '{encryption.encrypt('Admin!23')}', '{encryption.encrypt('Bob SuperAdmin')}', {encryption.encrypt('2')}, {encryption.encrypt('0')}, '{encryption.encrypt(now.strftime('%d-%m-%Y'))}')")
            self.conn.commit()
        except:
            None

        # create logging table if it doesnt excist
        # sqlite3 doesnt have datetime or boolean(0 = false, 1 = true), date and time are strings and boolean is iteger
        tb_create = "CREATE TABLE logging (username varchar, date varchar, time varchar, description_of_activity varchar, additionalInfo varchar, supicious varchar, read varchar)"
        try:
            self.cur.execute(tb_create)
            self.conn.commit()
        except:
            None

    def login(self):
        None_User = [None,None,None,None,None]
        self.user = user(None_User)
        username = uginput('username', 5, 12)
        username.input('please enter username :')
        if not username.isValid():
            logging(db, username.value, 'tried to log in but couldnt', 'values used are' + username.value, 1)
            print('username or password is incorrect')
            return

        password = uginput('password', 8, 30)
        password.input('please enter password :')
        if not password.isValid():
            print('username or password is incorrect')
            return

        logging(db, username.value, 'user logged in ', 'values used are ' + username.value, 0)
        # string concatenation
        # sql_statement = f"SELECT * from users WHERE username='{username}' AND password='{password}'"
        sql_statement = f'SELECT * from users WHERE username="{encryption.encrypt(username.value)}" AND password="{encryption.encrypt(password.value)}"'

        self.cur.execute(sql_statement)

        loggedin_user = self.cur.fetchone()
        if not loggedin_user:  # An empty result evaluates to False.
            logging(username.value, 'attempt_login_failed password = ' + password.value,
                    'username is not valid', '1')
            print('username or password is incorrect')
            self.cur.execute(
                "SELECT attempts FROM users WHERE username=:username", \
                {"username": encryption.encrypt(username.value)})

            attempts = encryption.decrypt(self.cur.fetchone()[0])
            incrAttempts = f'{(int(attempts)) + 1}'

            self.cur.execute("UPDATE users SET attempts=:attempts WHERE username=:username", \
                             {"attempts": encryption.encrypt(incrAttempts),
                              "username": encryption.encrypt(username.value)})
            self.conn.commit()

        else:
            if (int(encryption.decrypt(loggedin_user[4]))) < 3:
                self.cur.execute("UPDATE users SET attempts=:attempts WHERE username=:username", \
                                 {"attempts": encryption.encrypt('0'), "username": encryption.encrypt(username.value)})
                self.user = user(loggedin_user)
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
                sql_statement = 'SELECT read, supicious  from logging'
                self.cur.execute(sql_statement)
                log = self.cur.fetchall()
                decryptedList = encryption.decryptNestedTupleToNestedList(log)
                sus = False
                for l in decryptedList:
                    if '0' == l[0] and l[1] == '1':
                        sus = True
                        continue

                print('\n\n\n\nWelcome')
                heading = '▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄' + '\n' + \
                          '▍ ' + '\n' + \
                          '▍ Username: ' + colored(self.loggedin_user, 'red') + '\n' + \
                          '▍ ' + '\n' + \
                          '▍ User type: ' + colored(user_type, 'red') + '\n' + \
                          '▍ ' + '\n' + \
                          '▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀' + '\n' + \
                          'User Menu'

                if sus:
                    heading += '\n' + '▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄' + '\n' + \
                    'SUSPICIOUS ACTIVITY DETECTED PLEASE CHECK LOGS!'
                db_interface = user_interface(heading, db_menu_system_admin)
                db_interface.run()
                del db_interface
            elif self.admin_is_loggedin == '2':
                user_type = 'Super Administrator'
                sql_statement = 'SELECT read, supicious  from logging'
                self.cur.execute(sql_statement)
                log = self.cur.fetchall()
                decryptedList = encryption.decryptNestedTupleToNestedList(log)
                sus = False
                for l in decryptedList:
                    if '0' == l[0] and l[1] == '1':
                        sus = True
                        continue
                print('\n\n\n\nWelcome')
                heading = '▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄' + '\n' + \
                          '▍ ' + '\n' + \
                          '▍ Username: ' + colored(self.loggedin_user, 'red') + '\n' + \
                          '▍ ' + '\n' + \
                          '▍ User type: ' + colored(user_type, 'red') + '\n' + \
                          '▍ ' + '\n' + \
                          '▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀' + '\n' + \
                          'User Menu'

                if sus:
                    heading += '\n' + '▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄' + '\n' + \
                    'SUSPICIOUS ACTIVITY DETECTED PLEASE CHECK LOGS!'
                db_interface = user_interface(heading, db_menu_super_admin)
                db_interface.run()
                del db_interface
            else:
                print('account blocked, take contact with the system administrator to reset your password')

    def show_all_clients(self):
        sql_statement = 'SELECT * from client'
        self.cur.execute(sql_statement)
        clients = self.cur.fetchall()
        decryptedList = encryption.decryptNestedTupleToNestedList(clients)
        print(tabulate(decryptedList,
                       headers=['fullname', 'streetaddress', 'housenumber', 'zipcode', 'city', 'email address',
                                'mobile phone number']))

    def search_client(self):
        # check fullname
        fullname = uginput('fullname', 5, 40)
        fullname.input("please enter fullname (You must use min 5 and max 30 characters in length\nFirst character must be a letter): ")
        if not fullname.isValid():
            logging(db, fullname.value, 'tried to search an client, fullname incorrect','values used are' + fullname.value, 1)
            print('username was incorrect/or not found')
            return

        # checking housenumber
        housenumber = uginput('housenumber')
        housenumber.input("please enter HouseNumber: ")
        if not housenumber.isValid():
            logging(db, housenumber.value, 'tried to search an client, housenumber incorrect','values used are' + housenumber.value, 1)
            print('housenumber was incorrect/or not found')
            return

        # checking zipcode
        zipcode = uginput('zipcode', 6, 6)
        zipcode.input("please enter zipcode (The zipcode must have a length of 6 characters\nThe first 4 chars must be numbers\nThe first number cant be 0 ): ")
        if not zipcode.isValid():
            logging(db, zipcode.value, 'tried to search an client, housenumber incorrect',
                    'values used are' + zipcode.value, 1)
            print('housenumber was incorrect/or not found')
            return

        self.cur.execute(
            "SELECT * FROM client WHERE fullname=:fullname AND HouseNumber=:HouseNumber AND zipcode=:zipcode", \
            {"fullname": fullname.value, "HouseNumber": housenumber.value, "zipcode": zipcode.value})
        client = self.cur.fetchone()
        decryptedList = encryption.decryptTupleToList(client)
        print(tabulate([decryptedList],
                       headers=['fullname', 'streetaddress', 'housenumber', 'zipcode', 'city', 'email address',
                                'mobile phone number']))

    def select_role(self, users):
        for u in users:
            if u[2] == '0':
                u[2] = 'advisor'
            elif u[2] == '1':
                u[2] = 'admin'
            elif u[2] == '2':
                u[2] = 'super admin'
        return users

    def show_all_users(self):
        sql_statement = 'SELECT username, fullname ,admin, registerdDate from users'
        self.cur.execute(sql_statement)
        users = self.cur.fetchall()
        decryptedList = encryption.decryptNestedTupleToNestedList(users)
        decryptedList = self.select_role(decryptedList)
        print(tabulate(decryptedList,
                       headers=['username', 'fullname', 'admin', 'registerDate']))

    def menu_display(self):
        print('_________________________________\n')
        print('Select a city')
        print('_________________________________\n')
        for option in cities:
            print('[' + str(option[0]) + ']' + ' ' + option[1])

    def select_city(self):
        self.menuoptions = [option[0] for option in cities]
        self.menu_display()
        try:
            tempoption = uginput('range', 1, 1, range=range(1,11) )
            tempoption.intinput('Choose a number from the menu: ')
            if not tempoption.isValid():
                logging(db, tempoption.value, F'tried to add a number or symbol outside of menu scope, values used are: {tempoption.value}',1)
                print('invalid option')
            else:
                option = tempoption.value



            print()
        except:
            option = -1
            print()

        while option != self.menuoptions[-1]:
            if option in self.menuoptions:
                try:
                    func_return = cities[self.menuoptions.index(option)][1]
                    if func_return == 0:
                        continue
                    else:
                        return func_return
                except:
                    print('Error!')
            else:
                print('invalid option')

            print()
            self.menu_display()
            try:
                tempoption = uginput('range', 1, 1, range=range(1, 11))
                tempoption.intinput('Choose a number from the menu: ')
                if not tempoption.isValid():
                    logging(db, tempoption.value,
                            F'tried to add a number or symbol outside of menu scope, values used are: {tempoption.value}',
                            1)
                    print('invalid option')
                else:
                    option = tempoption.value
            except:
                option = -1
                print()

    def add_new_client(self):
        #fullname validation
        fullname = uginput('fullname', 5, 30)
        fullname.input("please enter fullname (You must use min 5 and max 30 characters in length\nFirst character must be a letter):")
        if not fullname.isValid():
            logging(db, fullname.value, 'tried to add a new client, fullname incorrect', 'values used are' + fullname.value,1)
            print('fullname is incorrect')
            return
        
        # streetadress validation
        streetaddress = uginput('streetadress', 5, 40)
        streetaddress.input("please enter StreetAddress (You must use a min of 5 and max of 40 characters in length\n First character must be a letter):")
        if not streetaddress.isValid():
            logging(db, streetaddress.value, 'tried to add a new client, fullname incorrect','values used are' + streetaddress.value, 1)
            print('fullname is incorrect')
            return
       
       #HouseNumber validation
        housenumber = uginput('housenumber')
        housenumber.input("please enter housenumber: ")
        if not housenumber.isValid():
            logging(db, housenumber.value, 'tried to add a new client, fullname incorrect','values used are' + housenumber.value, 1)
            print('HouseNumber is incorrect')
            return

       #checking zipcode
        zipcode = uginput('zipcode', 6, 6)
        zipcode.input("please enter zipcode (The zipcode must have a length of 6 characters\nThe first 4 chars must be numbers\nThe first number cant be 0 ): ")
        if not zipcode.isValid():
            logging(db, zipcode.value, 'tried to search an client, zipcode incorrect',
                    'values used are' + zipcode.value, 1)
            print('Zipcode was incorrect/or not found')
            return
        
        city = self.select_city()

        # validating emailaddress

        emailaddress = uginput('email',5,50 )
        emailaddress.input("please enter emailaddress (The email must be min 5 and max 50 characters in length): ")
        if not emailaddress.isValid():
            logging(db, emailaddress.value, 'tried to add a client, emailaddress incorrect',
                    'values used are' + emailaddress.value, 1)
            print('emailaddress was incorrect')
            return
        
        # validating mobile phone

        mobilephone = uginput('telephonenumber', 8, 8)
        mobilephone.input("please enter MobilePhone +31-6- (Must have a length of 8 digits): ")
        if not mobilephone.isValid():
            logging(db, mobilephone.value, 'tried to add a client, mobilephone incorrect','values used are' + mobilephone.value, 1)
            print('mobilephone was incorrect')
            return
       
        client1 = F"INSERT INTO client (fullname, StreetAddress, HouseNumber, ZipCode, City, EmailAddress, MobilePhone) VALUES ('{encryption.encrypt(fullname.value)}', '{encryption.encrypt(streetaddress.value)}', '{encryption.encrypt(housenumber.value)}', '{encryption.encrypt(zipcode.value)}', '{encryption.encrypt(city)}', '{encryption.encrypt(emailaddress.value)}', '{encryption.encrypt('+31-6-' + mobilephone.value)}')"
        try:
            self.cur.execute(client1)
            self.conn.commit()
            print('client has been added')
            logging(db, self.user.username, 'added new client', 'added ' + fullname.value, 0)
        except:
            logging(db, self.user.username, 'trying to add new client but failed', 'tried to add ' + fullname.value, 1)
            print('Failed to add client')

    def delete_client(self):
        # validating fullname
        fullname = uginput('fullname', 5, 40)
        fullname.input("please enter fullname (You must use min 5 and max 30 characters in length\nFirst character must be a letter): ")
        if not fullname.isValid():
            logging(db, fullname.value, 'trying to delete client, fullname incorrect',
                    'values used are' + fullname.value, 1)
            print('fullname was incorrect')
            return

        # HouseNumber validation
        housenumber = uginput('housenumber')
        housenumber.input("please enter housenumber: ")
        if not housenumber.isValid():
            logging(db, housenumber.value, 'tried to add a new client, fullname incorrect',
                    'values used are' + housenumber.value, 1)
            print('HouseNumber is incorrect')
            return

        # checking zipcode
        zipcode = uginput('zipcode', 6, 6)
        zipcode.input("please enter zipcode (The zipcode must have a length of 6 characters\nThe first 4 chars must be numbers\nThe first number cant be 0 ): ")
        if not zipcode.isValid():
            logging(db, zipcode.value, 'tried to search an client, housenumber incorrect',
                    'values used are' + zipcode.value, 1)
            print('housenumber was incorrect/or not found')
            return
        
        try:
            self.cur.execute(
                "DELETE FROM client WHERE fullname=:fullname AND HouseNumber=:HouseNumber AND zipcode=:zipcode", \
                {"fullname": encryption.encrypt(fullname.value), "HouseNumber": encryption.encrypt(housenumber.value), "zipcode": encryption.encrypt(zipcode.value)})
            self.conn.commit()
            print('client has been deleted')
            logging(db, self.user.username, 'client has been deleted','client name ' + fullname.value + ' ' + 'client house number ' + housenumber.value + ' ' + 'client zipcode ' + zipcode.value,0)
        except:
            logging(db, self.user.username, 'trying to delete client but failed', 'tried to delete ' + fullname.value, 1)
            print('client deletion has failed')

    def modify_client(self):
        # fullname validation
        fullname = uginput('fullname', 5, 30)
        fullname.input("please enter fullname (You must use min 5 and max 30 characters in length\nFirst character must be a letter): ")
        if not fullname.isValid():
            logging(db, fullname.value, 'tried to add a new client, fullname incorrect','values used are' + fullname.value, 1)
            print('fullname is incorrect')
            return

        # HouseNumber validation
        housenumber = uginput('HouseNumber')
        housenumber.input("please enter HouseNumber: ")
        if not housenumber.isValid():
            logging(db, housenumber.value, 'tried to search for a new client, housenumber incorrect',
                    'values used are' + housenumber.value, 1)
            print('HouseNumber is incorrect')
            return

        # checking zipcode
        zipcode = uginput('zipcode', 6, 6)
        zipcode.input("please enter zipcode (The zipcode must have a length of 6 characters\nThe first 4 chars must be numbers\nThe first number cant be 0 ): ")
        if not zipcode.isValid():
            logging(db, zipcode.value, 'tried to search a an client, zipcode incorrect',
                    'values used are' + zipcode.value, 1)
            print('housenumber was incorrect/or not found')
            return

        # fullname validation
        fullnamenew = uginput('fullname', 5, 30)
        fullnamenew.input("please enter fullname: ")
        if not fullnamenew.isValid():
            logging(db, fullnamenew.value, 'tried to add a new client, fullname incorrect',
                    'values used are' + fullnamenew.value, 1)
            print('fullname is incorrect')
            return

        # streetadress validation
        streetaddress = uginput('streetadress', 5, 40)
        streetaddress.input("please enter StreetAddress: (You must use a min of 5 and max of 40 characters in length\n First character must be a letter)")
        if not streetaddress.isValid():
            logging(db, streetaddress.value, 'tried to modify a new client, streetaddress incorrect',
                    'values used are' + streetaddress.value, 1)
            print('streetaddress is incorrect')
            return

        # HouseNumber validation
        HouseNumberNew = uginput('HouseNumber')
        HouseNumberNew.input("please enter HouseNumber: ")
        if not HouseNumberNew.isValid():
            logging(db, HouseNumberNew.value, 'tried to add a new client, fullname incorrect',
                    'values used are' + HouseNumberNew.value, 1)
            print('HouseNumber is incorrect')
            return

        # checking zipcode
        zipcodeNew = uginput('zipcode')
        zipcodeNew.input("please enter zipcode: ")
        if not zipcodeNew.isValid():
            logging(db, zipcodeNew.value, 'tried to modify an client, zipcode incorrect',
                    'values used are' + zipcodeNew.value, 1)
            print('zipcode was incorrect')
            return

        city = self.select_city()
        # validating emailaddress

        emailaddress = uginput('email', 5, 255)
        emailaddress.input("please enter emailaddress: ")
        if not emailaddress.isValid():
            logging(db, emailaddress.value, 'tried to modify a client, emailaddress incorrect',
                    'values used are' + emailaddress.value, 1)
            print('emailaddress was incorrect')
            return

        # validating mobile phone

        mobilephone = uginput('email', 5, 255)
        mobilephone.input("please enter MobilePhone +31-6- (Must have a length of 8 digits): ")
        if not mobilephone.isValid():
            logging(db, mobilephone.value, 'tried to add a client, mobilephone incorrect',
                    'values used are' + mobilephone.value, 1)
            print('mobilephone was incorrect')
            return
        try:
            self.cur.execute(
                "UPDATE client SET fullname=:newFullname, StreetAddress=:newStreetAddress, HouseNumber=:HouseNumberNew, ZipCode=:ZipCodeNew, City=:CityNew, EmailAddress=:EmailAddressNew, MobilePhone=:MobilePhoneNew WHERE fullname=:fullname AND HouseNumber=:HouseNumber AND zipcode=:zipcode", \
                {"newFullname": encryption.encrypt(fullnamenew.value),
                 "newStreetAddress": encryption.encrypt(streetaddress.value),
                 "HouseNumberNew": encryption.encrypt(HouseNumberNew.value), "ZipCodeNew": encryption.encrypt(zipcodeNew.value),
                 "CityNew": encryption.encrypt(city), "EmailAddressNew": encryption.encrypt(emailaddress.value),
                 "MobilePhoneNew": encryption.encrypt(f'{mobilephone.value}'), "fullname": encryption.encrypt(fullname.value),
                 "HouseNumber": encryption.encrypt(housenumber.value), "zipcode": encryption.encrypt(zipcode.value)})
            self.conn.commit()
            print('client has been modified')
            logging(db, self.user.username, 'client has been modified',
                    'modified values' + fullnamenew.value + ' ' + streetaddress.value + ' ' + HouseNumberNew.value + ' ' + zipcodeNew.value + ' ' + city + ' ' + emailaddress.value + ' ' + mobilephone.value,
                    0)
        except:
            logging(db, self.user.username, 'trying to modify account', 'tried to modify ' + fullname.value, 1)
            print('client modification has failed')

    def delete_user(self, role):
        username = uginput('username', 5, 40)
        username.input("please enter username: ")
        if not username.isValid():
            logging(db, username.value, 'tried to add a client, username incorrect',
                    'values used are' + username.value, 1)
            print('username was incorrect')
            return
        try:
            self.cur.execute(
                "DELETE FROM users WHERE username=:username and admin=:role", \
                {"username": encryption.encrypt(username), "role": encryption.encrypt(role)})
            self.conn.commit()
            logging(db, self.user.username, 'user has been deleted', 'name deleted user ' + username.value, 0)
            print('user has been deleted')
        except:
            logging(db, self.user.username, 'trying to delete user but failed', 'tried to delete ' + username.value, 1)
            print('user deletion has failed')

    def change_password(self):
        # oldpassword validation
        oldpassword = uginput('oldpassword', 8, 30)
        oldpassword.input("please enter old password: ")
        if not oldpassword.isValid():
            logging(db, oldpassword.value, 'tried to change password, old password incorrect',
                    'values used are' + oldpassword.value, 1)
            print('oldpassword is incorrect')
            return
        if (oldpassword.value == self.user.password):
            # validate new pasword
            newpassword = uginput('newpassword', 8, 30)
            newpassword.input("please enter new password: ")
            if not newpassword.isValid():
                logging(db, newpassword.value, 'tried to change password, new password incorrect',
                        'values used are' + newpassword.value, 1)
                print('newpassword is incorrect')
                return

            # validate newpasswordrepeated
            newpasswordrepeated = uginput('newpasswordrepeated', 8, 30)
            newpasswordrepeated.input("please reenter new password: ")
            if not newpasswordrepeated.isValid():
                logging(db, newpasswordrepeated.value, 'tried to change password, newpasswordrepeated incorrect',
                        'values used are' + newpasswordrepeated.value, 1)
                print('newpasswordrepeated is incorrect')
                return

            if newpassword.value == newpasswordrepeated.value:
                try:
                    self.cur.execute("UPDATE users SET password=:password, attempts=:attempts WHERE username=:username", \
                    {"password": encryption.encrypt(newpassword.value), "attempts": encryption.encrypt('0'),"username": self.user.username})
                    self.conn.commit()
                    print('advisor has been modified')
                except:
                    logging(db, self.user.username, 'trying to change user password','tried to change pw to from ' + oldpassword.value + ' to ' + newpassword.value, 1)
                    print('advisor modification has failed')
            else:
                logging(db, self.user.username, 'trying to change user password', 'password is not the same', 0)
                print('password is not the same')
        else:
            logging(db, self.user.username, 'trying to change user password',
                    'tried pw ' + oldpassword.value + ' is not the same as the tried on ' + self.user.password, 1)
            print('password is not correct')

    def backup(self):
        # create a ZipFile object
        zipObj = ZipFile(f"systembackuo{now.strftime('%d-%m-%Y-%H-%M')}.zip", 'w')
        # Add multiple files to the zip
        logging(db, self.user.username, 'made backup', 'made backup ' + 'null', 0)
        zipObj.write('mycompany.db')
        # close the Zip File

        zipObj.close()

    def add_new_advisor(self):

        username = uginput('username', 5, 12)
        username.input("please enter username: ")
        if not username.isValid():
            logging(db, username.value, 'tried to add a username for new advisor, values used are' + username.value, 1)
            print('username,password or fullname is incorrect')
            return

        password = uginput('password', 8, 30)
        password.input("please enter password: ")
        if not password.isValid():
            logging(db, username.value, 'tried to add a password for new advisor', 'values used are' + password.value,
                    1)
            print('username,password or fullname is incorrect')
            return

        fullname = uginput('fullname', 5, 12)
        fullname.input("please enter fullname (You must use min 5 and max 30 characters in length\nFirst character must be a letter): ")
        if not fullname.isValid():
            logging(db, username.value, 'tried to add a fullname for a new advisor', 'values used are' + fullname.value,
                    1)
            print('username,password or fullname is incorrect')
            return
        admin = '0'
        try:
            self.cur.execute(
                F"INSERT INTO users (username, password, fullname, admin, registerdDate) VALUES ('{encryption.encrypt(username.value)}', '{encryption.encrypt(password.value)}', '{encryption.encrypt(fullname.value)}', {encryption.encrypt(admin)}, '{encryption.encrypt(now.strftime('%d-%m-%Y'))}')")
            self.conn.commit()
            logging(db, self.user.username, 'added new advisor',
                    'new values username ' + username.value + ' fullname ' + fullname.value, 0)
            print('advisor has been added')
        except:
            logging(db, self.user.username, 'failed adding new advisor',
                    'new values username ' + username.value + ' fullname ' + fullname.value, 1)
            print('advisor failed to be added')

    def modify_advisor(self):
        # validating oldusername
        oldusername = uginput('oldusername', 5, 12)
        oldusername.input("please enter the Username that you want to modify: ")
        if not oldusername.isValid():
            logging(db, oldusername.value, 'tried to modify an advisor olduusername incorrect',
                    'values used are' + oldusername.value, 1)
            print('old username was incorrect/or not found')
            return

        # validating username
        username = uginput('username', 5, 12)
        username.input("please enter new username: ")
        if not username.isValid():
            logging(db, username.value, 'tried to modify an advisor username incorrect',
                    'values used are' + username.value, 1)
            print('old username was incorrect/or not found')
            return

        # validating password
        password = uginput('password', 8, 30)
        password.input("please enter new password: ")
        if not password.isValid():
            logging(db, password.value, 'tried to modify a password for advisor', 'values used are' + password.value,
                    1)
            print('username,password or fullname is incorrect')
            return

        # validating fullname
        fullname = uginput('fullname', 5, 12)
        fullname.input("please enter fullname (You must use min 5 and max 30 characters in length\nFirst character must be a letter): ")
        if not fullname.isValid():
            logging(db, fullname.value, 'tried to modify a fullname for a new advisor',
                    'values used are' + fullname.value,
                    1)
            print('username,password or fullname is incorrect')
            return
        role = '0'
        try:
            self.cur.execute(
                "UPDATE users SET username=:username, password=:password, fullname=:fullname WHERE username=:oldUsername and admin=:role", \
                {"username": encryption.encrypt(username.value), "password": encryption.encrypt(password.value),
                 "fullname": encryption.encrypt(fullname.value),
                 "oldUsername": encryption.encrypt(oldusername.value), "role": encryption.encrypt(role)})
            self.conn.commit()
            logging(db, self.user.username, 'modified advisor',
                    'values modified are oldUsername' + oldusername.value + ' to ' + username.value + ' fullname ' + fullname.value,
                    0)
            print('advisor has been modified')
        except:
            logging(db, self.user.username, 'modified advisor failed',
                    'tried values are oldUsername' + oldusername.value + ' to ' + username.value + ' fullname ' + fullname.value,
                    0)
            print('advisor modification has failed')

    def delete_advisor(self):
        self.delete_user('0')

    def reset_advisor_password(self):
        # check advisor name
        advisorname = uginput('advisorname', 5, 12)
        advisorname.input("please enter Advisor username: ")
        if not advisorname.isValid():
            logging(db, advisorname.value, 'tried to reset an advisor, username not found',
                    'values used are' + advisorname.value, 1)
            print('advisor was incorrect/or not found')
            return

        # password validation
        password = uginput('password', 8, 30)
        password.input("please enter new Advisor password: ")
        if not password.isValid():
            logging(db, password.value, 'tried to reset an advisor, username not found',
                    'values used are' + password.value, 1)
            print('advisor was incorrect/or not found')
            return
        role = '0'
        try:
            self.cur.execute(
                "UPDATE users SET password=:password WHERE username=:username and admin=:role", \
                {"username": encryption.encrypt(advisorname.value), "password": encryption.encrypt(password.value),
                 "role": encryption.encrypt(role)})
            self.conn.commit()
            print('advisor has been modified')
        except:
            print('advisor password reset has failed')

    def add_new_admin(self):
        # username validation
        username = uginput('username', 5, 12)
        username.input("please enter username: ")
        if not username.isValid():
            logging(db, username.value, 'tried to add new admin, username was invalid','values used are' + username.value, 1)
            print('username incorrect')
            return

        # password valdation
        password = uginput('password', 5, 12)
        password.input("please enter password: ")
        if not password.isValid():
            logging(db, password.value, 'tried to add new admin, password was invalid','values used are' + password.value, 1)
            print('password incorrect')
            return

        #fullname validation
        fullname = uginput('fullname', 5, 12)
        fullname.input("please enter fullname (You must use min 5 and max 30 characters in length\nFirst character must be a letter): ")
        if not fullname.isValid():
            logging(db, self.user.username, 'tried to add new admin, new fullname was invalid','values used are' + fullname.value, 1)
            print('fullname incorrect')
            return
        admin = '1'
        try:
            self.cur.execute(
                F"INSERT INTO users (username, password, fullname, admin) VALUES ('{encryption.encrypt(username.value)}', '{encryption.encrypt(password.value)}', '{encryption.encrypt(fullname.value)}', {encryption.encrypt(admin)})")
            self.conn.commit()
            print('admin has been added')
        except:
            print('admin failed to be added')

    def modify_admin(self):
        # validating oldusername
        oldusername = uginput('oldusername', 5, 12)
        oldusername.input("please enter the username that you want to modify: ")
        if not oldusername.isValid():
            logging(db, oldusername.value, 'tried to modify an admin, username incorrect','values used are' + oldusername.value, 1)
            print('old username was incorrect/or not found')
            return

        # validating username
        username = uginput('username', 5, 12)
        username.input("please enter new username: ")
        if not username.isValid():
            logging(db, username.value, 'tried to modify an admin, username incorrect','values used are' + username.value, 1)
            print('old username was incorrect/or not found')
            return

        # validating password
        password = uginput('password', 8, 30)
        password.input("please enter new password: ")
        if not password.isValid():
            logging(db, username.value, 'tried to modify an admin, password incorrect', 'values used are' + password.value,1)
            print('password is incorrect')
            return

        # validating fullname
        fullname = uginput('fullname', 5, 12)
        fullname.input("please enter fullname (You must use min 5 and max 30 characters in length\nFirst character must be a letter): ")
        if not fullname.isValid():
            logging(db, fullname.value, 'tried to modify a admin, fullname incorrect','values used are' + fullname.value,1)
            print('fullname is incorrect')
            return
        role = '1'
        try:
            self.cur.execute(
                "UPDATE users SET username=:username, password=:password, fullname=:fullname WHERE username=:oldUsername and admin=:role", \
                {"username": encryption.encrypt(username.value), "password": encryption.encrypt(password.value),
                 "fullname": encryption.encrypt(fullname.value),
                 "oldUsername": encryption.encrypt(oldusername.value), "role": encryption.encrypt(role)})
            self.conn.commit()
            logging(db, self.user.username, 'modified admin','values modified are oldUsername' + oldusername.value + ' to ' + username.value + ' fullname ' + fullname.value,0)
            print('admin has been modified')
        except:
            logging(db, self.user.username, 'modified admin failed','tried values are oldUsername' + oldusername.value + ' to ' + username.value + ' fullname ' + fullname.value,0)
            print('admin modification has failed')

    def delete_admin(self):
        self.delete_user('1')

    def reset_admin_password(self):
        # check admin name
        adminname = uginput('adminname', 5, 12)
        adminname.input("please enter admin username: ")
        if not adminname.isValid():
            logging(db, adminname.value, 'tried to reset an admin, username not found','values used are' + adminname.value, 1)
            print('admin was incorrect/or not found')
            return

        # password validation
        password = uginput('password', 8, 30)
        password.input("please enter new admin password: ")
        if not password.isValid():
            logging(db, password.value, 'tried to reset an admin, password not found','values used are' + password.value, 1)
            print('admin was incorrect/or not found')
            return
        role = '1'
        try:
            self.cur.execute(
                "UPDATE users SET password=:password WHERE username=:username and admin=:role", \
                {"username": encryption.encrypt(adminname.value), "password": encryption.encrypt(password.value),
                 "role": encryption.encrypt(role)})
            self.conn.commit()
            print('admin has been modified')
        except:
            print('admin password reset has failed')

    def read_logs(self):
        sql_statement = 'SELECT * from logging'
        self.cur.execute(sql_statement)
        log = self.cur.fetchall()
        decryptedList = encryption.decryptNestedTupleToNestedList(log)
        print(tabulate(decryptedList,
                       headers=['username', 'date', 'time', 'description_of_activity', 'additionalInfo', 'supicious', 'read']))
        self.cur.execute(
            "UPDATE logging SET read=:read", \
            {"read": encryption.encrypt('1'),})
        self.conn.commit()

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


def escape_sql_meta(sql_query):
    pass


client = db(company_db_name, client_tb_name, users_tb_name)
main_menu = [[1, 'login', client.login], [0, 'Exit', client.close]]
db_menu_advisor = [[1, 'change password', client.change_password], [2, 'add new client', client.add_new_client], \
                   [3, 'search for client', client.search_client], \
                   [4, 'modify a client', client.modify_client], [0, 'logout', client.logout]]

db_menu_system_admin = [[1, 'change password', client.change_password], [2, 'show all users', client.show_all_users], \
                        [3, 'add new client', client.add_new_client], [4, 'add new advisor', client.add_new_advisor], \
                        [5, 'delete a client', client.delete_client], \
                        [6, 'modify advisor', client.modify_advisor], [7, 'delete a advisor', client.delete_advisor], \
                        [8, 'reset advisor password', client.reset_advisor_password],
                        [9, 'read logs', client.read_logs], \
                        [10, 'modify a client', client.modify_client], \
                        [11, 'search for client', client.search_client], \
                        [12, 'make backup', client.backup], [0, 'logout', client.logout]]

db_menu_super_admin = [[1, 'show all clients', client.show_all_clients], [2, 'show all users', client.show_all_users], \
                       [3, 'add new client', client.add_new_client], [4, 'add new advisor', client.add_new_advisor], \
                       [5, 'delete a client', client.delete_client], \
                       [6, 'modify advisor', client.modify_advisor], [7, 'delete a advisor', client.delete_advisor], \
                       [8, 'reset advisor password', client.reset_advisor_password], [9, 'read logs', client.read_logs], \
                       [10, 'modify a client', client.modify_client],
                       [11, 'search for client', client.search_client], [12, 'add new admin', client.add_new_admin], \
                       [13, 'modify admin', client.modify_admin], [14, 'delete a admin', client.delete_admin], \
                       [15, 'reset admin password', client.reset_admin_password],
                       [16, 'make backup', client.backup], [0, 'logout', client.logout]]
