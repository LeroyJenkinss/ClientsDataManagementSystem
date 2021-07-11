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


class logging():

    def __init__(self, db, username, description_of_activity, additionalinfo, suspicious):
        self.username = encryption.encrypt(username)
        self.date = encryption.encrypt(date.today().strftime("%d-%b-%Y"))
        self.time = encryption.encrypt(strftime("%H:%M:%S", localtime()))
        self.description_of_activity = encryption.encrypt(description_of_activity)
        self.additionalinfo = encryption.encrypt(additionalinfo)
        self.suspicious = encryption.encrypt(suspicious)
        client.cur.execute(F"INSERT INTO logging (username, date, time, description_of_activity, additionalinfo, supicious) VALUES ('{self.username}','{self.date}','{self.time}','{self.description_of_activity}','{self.additionalinfo}','{self.suspicious}')")

# uginput class
class uginput:
    def __init__(self, domain_type: str, min_len=None, max_len=None, range=None):

        self.min_len = min_len
        self.max_len = max_len
        self.range = range
        self.domain_type = domain_type

    def _isValidUsername(self):
        if self.value is None:
            logging(db,self.value, 'checking_username', 'username has null value', '1')
            return False

        symbols_premitted = ['!', '.', '_']
        white_list = []
        white_list.extend(lowercase_letters)
        white_list.extend(uppercase_letters)
        white_list.extend(digits)
        white_list.extend(symbols_premitted)

        if self.value:
            valid = [
                self._length(self.min_len, self.max_len),
                self._checkFirstChar(self.value[0], lowercase_letters, uppercase_letters),
                self._checkwhitelist(white_list)]
            return all(valid)
        else:
            logging(db,self.value, 'checking_username', 'username is not valid', '1')
            return False

    def _check(self):
        symPremitted = ['~', '!', '@', '#', '$', '%', '^', '&', '*', '_', '-', '+', '=', '`', '|', '\\', '(', ')',
                        '{', '}', '[', ':', ';', "'", '<', '>', ',', '.', '?', '/']
        if any(x.isupper() for x in self.value) and (any(x.islower() for x in self.value)) and (
                any(x for x in digits)) and (any(x for x in symPremitted)):
            return True
        logging(db,self.value, 'check_if_1capital_1lowerCase_1digit_1specialChar_is_present',
                'username is not valid', '1')
        return False

    def _checkemail(self):
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

        if re.match(regex, self.value):
            return True
        return False




    def _checkwhitelist(self, white_list):
        for a in self.value:
            if a not in white_list:
                logging(db,self.value, 'checking_all_chars_in_whitelist', a + ' is not in the whitelist', '1')
                return False
        return True

    def input(self, question):
        self.value = input(question)

    def _length(self, min=0, max=64):
        name = self.value
        if min <= len(name) <= max:
            return True
        logging(db,self.value, 'checking_min&max_length', 'username is too short or too long', '1')
        return False

    def _checkFirstChar(self, char2Check, lowerLetters, upperLetters):
        if char2Check in lowerLetters:
            return True
        elif char2Check in upperLetters:
            return True
        else:
            logging(db,self.value, 'checking_if_firstletter_letter', 'firstChar isnt a letter', '1')
            return False

    def _isValidPassword(self):
        if self.value is None:
            logging(db,'None', 'checking_password', 'password has null value', '1')
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
            logging(db,self.value, 'checking_username', 'username is not valid', '1')
            return False

    def isValid(self):
        domain_func = {
            'username': self._isValidUsername,
            'password': self._isValidPassword,
            'email': self._isValidEmail
        }

        methodCall = (domain_func[self.domain_type]())
        return methodCall

    def _isValidEmail(self):
        if self.value is None:
            logging(db, 'None', 'checking_emailadress', 'email has null value', '1')
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

            return all(valid)
        else:
            logging(db, self.value, 'checking_username', 'username is not valid', '1')
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
            # add sample records to the db manually
            client1 = F"INSERT INTO client (fullname, StreetAddress, HouseNumber, ZipCode, City, EmailAddress, MobilePhone) VALUES ('{encryption.encrypt('Lili Anderson')}', '{encryption.encrypt('teststraat')}', '{encryption.encrypt('21B')}', '{encryption.encrypt('3114XE')}', '{encryption.encrypt('staddam')}', '{encryption.encrypt('test@test.nl')}', '{encryption.encrypt('+31-6-12345678')}')"
            self.cur.execute(client1)
            client2 = F"INSERT INTO client (fullname, StreetAddress, HouseNumber, ZipCode, City, EmailAddress, MobilePhone) VALUES ('{encryption.encrypt('Anne Banwarth')}', '{encryption.encrypt('teststrfggaat')}', '{encryption.encrypt('25B')}', '{encryption.encrypt('3134XE')}', '{encryption.encrypt('staddsaddam')}', '{encryption.encrypt('tesdadasst@test.nl')}', '{encryption.encrypt('+31-6-12345678')}')"
            self.cur.execute(client2)
            self.conn.commit()
        except:
            None

        # create user table if it does not exist
        tb_create = "CREATE TABLE users (username TEXT, password TEXT, fullname TEXT, admin varchar, attempts varchar);"
        try:
            self.cur.execute(tb_create)
            # add sample records to the db manually
            self.cur.execute(
                F"INSERT INTO users (username, password, fullname, admin, attempts) VALUES ('{encryption.encrypt('superadmin')}', '{encryption.encrypt('Admin!23')}', '{encryption.encrypt('Bob SuperAdmin')}', {encryption.encrypt('2')}, {encryption.encrypt('0')})")
            self.cur.execute(
                F"INSERT INTO users (username, password, fullname, admin, attempts) VALUES ('{encryption.encrypt('bob.l')}', '{encryption.encrypt('B0b!23')}', '{encryption.encrypt('Bob Larson')}', {encryption.encrypt('1')}, {encryption.encrypt('0')})")
            self.cur.execute(
                F"INSERT INTO users (username, password, fullname, admin, attempts) VALUES ('{encryption.encrypt('ivy_russel')}', '{encryption.encrypt('ivy@R123')}' , '{encryption.encrypt('Ivy Russel')}', {encryption.encrypt('0')}, {encryption.encrypt('0')})")
            self.conn.commit()
        except:
            None

        # create logging table if it doesnt excist
        # sqlite3 doesnt have datetime or boolean(0 = false, 1 = true), date and time are strings and boolean is iteger
        tb_create = "CREATE TABLE logging (username TEXT, date TEXT, time TEXT, description_of_activity TEXT, additionalInfo TEXT, supicious TEXT)"
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
            logging(db, username.value, 'tried to log in but couldnt','values used are' + username.value , 1)
            print('username or password is incorrect')
            return

        password = uginput('password', 8, 30)
        password.input('please enter password:')
        if not password.isValid():
            print('username or password is incorrect')
            return

        logging(db, username.value, 'user logged in ', 'values used are' + username.value, 1)
        # string concatenation
        # sql_statement = f"SELECT * from users WHERE username='{username}' AND password='{password}'"
        sql_statement = f'SELECT * from users WHERE username="{encryption.encrypt(username.value)}" AND password="{encryption.encrypt(password.value)}"'

        self.cur.execute(sql_statement)

        loggedin_user = self.cur.fetchone()
        if not loggedin_user:  # An empty result evaluates to False.
            logging(username.value, 'attempt_login_failed password = ' + password.value,
                    'username is not valid', '1')
            print("Login failed")
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

        fullName = encryption.encrypt(input("please enter fullname: "))
        HouseNumber = encryption.encrypt(input("please enter HouseNumber: "))
        zipcode = encryption.encrypt(input("please enter ZipCode: "))
        self.cur.execute(
            "SELECT * FROM client WHERE fullname=:fullname AND HouseNumber=:HouseNumber AND zipcode=:zipcode", \
            {"fullname": fullName, "HouseNumber": HouseNumber, "zipcode": zipcode})
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
        sql_statement = 'SELECT username, fullname ,admin from users'
        self.cur.execute(sql_statement)
        users = self.cur.fetchall()
        decryptedList = encryption.decryptNestedTupleToNestedList(users)
        decryptedList = self.select_role(decryptedList)
        print(tabulate(decryptedList,
                       headers=['username', 'fullname', 'admin']))

    def add_new_client(self):
        fullname = input("please enter fullname: ")
        StreetAddress = input("please enter StreetAddress: ")
        HouseNumber = input("please enter HouseNumber: ")
        ZipCode = input("please enter ZipCode: ")
        City = input("please enter City: ")
        EmailAddress = input("please enter EmailAddress: ")
        MobilePhone = input("please enter MobilePhone +31-6-: ")
        client1 = F"INSERT INTO client (fullname, StreetAddress, HouseNumber, ZipCode, City, EmailAddress, MobilePhone) VALUES ('{encryption.encrypt(fullname)}', '{encryption.encrypt(StreetAddress)}', '{encryption.encrypt(HouseNumber)}', '{encryption.encrypt(ZipCode)}', '{encryption.encrypt(City)}', '{encryption.encrypt(EmailAddress)}', '{encryption.encrypt('+31-6-' + MobilePhone)}')"
        try:
            self.cur.execute(client1)
            self.conn.commit()
            print('client has been added')
            logging(db, self.user.username, 'added new client', 'added ' + fullname, 0)
        except:
            logging(db, self.user.username, 'trying to add new client but failed','tried to add ' + fullname, 1)
            print('Failed to add client')

    def delete_client(self):
        fullName = encryption.encrypt(input("please enter fullname: "))
        HouseNumber = encryption.encrypt(input("please enter HouseNumber: "))
        zipcode = encryption.encrypt(input("please enter ZipCode: "))
        try:
            self.cur.execute(
                "DELETE FROM client WHERE fullname=:fullname AND HouseNumber=:HouseNumber AND zipcode=:zipcode", \
                {"fullname": fullName, "HouseNumber": HouseNumber, "zipcode": zipcode})
            self.conn.commit()
            print('client has been deleted')
            logging(db, self.user.username, 'client has been deleted', 'client name ' + fullName+ ' '+'client house number '+HouseNumber+' '+'client zipcode '+zipcode, 0)
        except:
            logging(db, self.user.username, 'trying to delete client but failed','tried to delete ' + fullName, 1)
            print('client deletion has failed')

    def modify_client(self):
        fullName = input("please enter fullname: ")
        HouseNumber = input("please enter HouseNumber: ")
        zipcode = input("please enter ZipCode: ")

        fullnameNew = input("please enter new fullname: ")
        StreetAddressNew = input("please enter new StreetAddress: ")
        HouseNumberNew = input("please enter new HouseNumber: ")
        ZipCodeNew = input("please enter new ZipCode: ")
        CityNew = input("please enter new City: ")
        EmailAddressNew = input("please enter new EmailAddress: ")
        MobilePhoneNew = input("please enter new MobilePhone +31-6-: ")
        try:
            self.cur.execute(
                "UPDATE client SET fullname=:newFullname, StreetAddress=:newStreetAddress, HouseNumber=:HouseNumberNew, ZipCode=:ZipCodeNew, City=:CityNew, EmailAddress=:EmailAddressNew, MobilePhone=:MobilePhoneNew WHERE fullname=:fullname AND HouseNumber=:HouseNumber AND zipcode=:zipcode", \
                {"newFullname": encryption.encrypt(fullnameNew),
                 "newStreetAddress": encryption.encrypt(StreetAddressNew),
                 "HouseNumberNew": encryption.encrypt(HouseNumberNew), "ZipCodeNew": encryption.encrypt(ZipCodeNew),
                 "CityNew": encryption.encrypt(CityNew), "EmailAddressNew": encryption.encrypt(EmailAddressNew),
                 "MobilePhoneNew": encryption.encrypt(MobilePhoneNew), "fullname": encryption.encrypt(fullName),
                 "HouseNumber": encryption.encrypt(HouseNumber), "zipcode": encryption.encrypt(zipcode)})
            self.conn.commit()
            print('client has been modified')
            logging(db, self.user.username, 'client has been modified', 'modified values' + fullnameNew+' '+StreetAddressNew+' '+HouseNumberNew+' '+ZipCodeNew+' '+CityNew+' '+EmailAddressNew+' '+MobilePhoneNew, 0)
        except:
            logging(db, self.user.username, 'trying to modify account','tried to modify ' + fullName, 1)
            print('client modification has failed')

    def delete_user(self, role):
        username = input("please enter username: ")
        try:
            self.cur.execute(
                "DELETE FROM users WHERE username=:username and admin=:role", \
                {"username": encryption.encrypt(username), "role": encryption.encrypt(role)})
            self.conn.commit()
            logging(db, self.user.username, 'user has been deleted', 'name deleted user ' + username, 0)
            print('user has been deleted')
        except:
            logging(db, self.user.username, 'trying to delete user but failed','tried to delete ' + username, 1)
            print('user deletion has failed')

    def change_password(self):
        oldPassword = input("please enter old password: ")
        if (oldPassword == self.user.password):
            newPassword = input("please enter new password: ")
            newPasswordRepeated = input("please reenter new password: ")
            if newPassword == newPasswordRepeated:
                try:
                    self.cur.execute(
                        "UPDATE users SET password=:password, attempts=:attempts WHERE username=:username", \
                        {"password": encryption.encrypt(newPassword), "attempts": encryption.encrypt('0'),
                         "username": self.user.username})
                    self.conn.commit()
                    print('advisor has been modified')
                except:
                    logging(db,self.user.username,'trying to change user password','tried to change pw to from '+oldPassword+' to '+newPassword, 1)
                    print('advisor modification has failed')
            else:
                logging(db, self.user.username, 'trying to change user password','password is not the same', 0)
                print('password is not the same')
        else:
            logging(db, self.user.username, 'trying to change user password','tried pw '+oldPassword+' is not the same as the tried on '+self.user.password, 1)
            print('password is not correct')

    def backup(self):
        # create a ZipFile object
        zipObj = ZipFile(f"systembackuo{now.strftime('%d-%m-%Y-%H-%M')}.zip", 'w')
        # Add multiple files to the zip
        logging(db, self.user.username, 'made backup','made backup ' + 'null', 0)
        zipObj.write('mycompany.db')
        # close the Zip File

        zipObj.close()

    def add_new_advisor(self):
        username = input("please enter username: ")
        password = input("please enter password: ")
        fullname = input("please enter fullname: ")
        admin = '0'
        try:
            self.cur.execute(
                F"INSERT INTO users (username, password, fullname, admin) VALUES ('{encryption.encrypt(username)}', '{encryption.encrypt(password)}', '{encryption.encrypt(fullname)}', {encryption.encrypt(admin)})")
            self.conn.commit()
            logging(db, self.user.username, 'added new advisor','new values username '+username+' fullname '+fullname,0)
            print('advisor has been added')
        except:
            logging(db, self.user.username, 'failed adding new advisor','new values username ' + username + ' fullname ' + fullname, 1)
            print('advisor failed to be added')

    def modify_advisor(self):
        oldUsername = input("please enter username: ")
        username = input("please enter new username: ")
        password = input("please enter new password: ")
        fullname = input("please enter new fullname: ")
        role = '0'
        try:
            self.cur.execute(
                "UPDATE users SET username=:username, password=:password, fullname=:fullname WHERE username=:oldUsername and admin=:role", \
                {"username": encryption.encrypt(username), "password": encryption.encrypt(password),
                 "fullname": encryption.encrypt(fullname),
                 "oldUsername": encryption.encrypt(oldUsername), "role": encryption.encrypt(role)})
            self.conn.commit()
            logging(db, self.user.username, 'modified advisor','values modified are oldUsername' + oldUsername +' to '+username+ ' fullname ' + fullname, 0)
            print('advisor has been modified')
        except:
            logging(db, self.user.username, 'modified advisor failed','tried values are oldUsername' + oldUsername + ' to ' + username + ' fullname ' + fullname, 0)
            print('advisor modification has failed')

    def delete_advisor(self):
        self.delete_user('0')

    def reset_advisor_password(self):
        advisorName = input("please enter Advisor username: ")
        password = input("please enter new Advisor password: ")
        role = '0'
        try:
            self.cur.execute(
                "UPDATE users SET password=:password WHERE username=:username and admin=:role", \
                {"username": encryption.encrypt(advisorName), "password": encryption.encrypt(password),
                 "role": encryption.encrypt(role)})
            self.conn.commit()
            print('advisor has been modified')
        except:
            print('advisor password reset has failed')

    def add_new_admin(self):
        username = input("please enter username: ")
        password = input("please enter password: ")
        fullname = input("please enter fullname: ")
        admin = '1'
        try:
            self.cur.execute(
                F"INSERT INTO users (username, password, fullname, admin) VALUES ('{encryption.encrypt(username)}', '{encryption.encrypt(password)}', '{encryption.encrypt(fullname)}', {encryption.encrypt(admin)})")
            self.conn.commit()
            print('admin has been added')
        except:
            print('admin failed to be added')

    def modify_admin(self):
        oldUsername = input("please enter username: ")
        username = input("please enter new username: ")
        password = input("please enter new password: ")
        fullname = input("please enter new fullname: ")
        role = '1'
        try:
            self.cur.execute(
                "UPDATE users SET username=:username, password=:password, fullname=:fullname WHERE username=:oldUsername and admin=:role", \
                {"username": encryption.encrypt(username), "password": encryption.encrypt(password),
                 "fullname": encryption.encrypt(fullname),
                 "oldUsername": encryption.encrypt(oldUsername), "role": encryption.encrypt(role)})
            self.conn.commit()
            print('admin has been modified')
        except:
            print('admin modification has failed')

    def delete_admin(self):
        self.delete_user('1')

    def reset_admin_password(self):
        advisorName = input("please enter Advisor username: ")
        password = input("please enter new Advisor password: ")
        role = '1'
        try:
            self.cur.execute(
                "UPDATE users SET password=:password WHERE username=:username and admin=:role", \
                {"username": encryption.encrypt(advisorName), "password": encryption.encrypt(password),
                 "role": encryption.encrypt(role)})
            self.conn.commit()
            print('admin password has been modified')
        except:
            print('admin password reset has failed')

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
