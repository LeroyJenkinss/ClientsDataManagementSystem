import sqlite3
from ui import *
from termcolor import colored
import EncryptingDb

# GLobal Variables
# --------------------------------------------------------------------
max_input_try = 3
company_db_name = 'mycompany.db'
client_tb_name = 'client'
users_tb_name = 'users'
db_key = 'r4[)(Y;N.U7uK@)$'


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
    def __init__(self, db_name, client_table_name, users_table_name, db_key):
        self.db_name = db_name
        self.client_table_name = client_table_name
        self.users_table_name = users_table_name
        self.db_key = db_key

        self.loggedin = 0
        self.loggedin_user = None
        self.admin_is_loggedin = 0

        self.reset()

    def reset(self):
        self.conn = sqlite3.connect(self.db_name)
        self.cur = self.conn.cursor()

        # create client table if it does not exist
        tb_create = "CREATE TABLE client (person_id int, fullname CHAR)"
        try:
            self.cur.execute(tb_create)
            # add sample records to the db manually
            encryption = EncryptingDb.EncryptingDb()
            self.cur.execute("INSERT INTO client (person_id, fullname) VALUES (1, encryption.encrypt('Lili Anderson'))")
            self.cur.execute("INSERT INTO client (person_id, fullname) VALUES (2, encryption.encrypt('Anne Banwarth'))")
            self.conn.commit()
        except: 
            None

        # create user table if it does not exist
        tb_create = "CREATE TABLE users (username TEXT, password TEXT, fullname TEXT, admin INT);"
        try:
            self.cur.execute(tb_create)
            # add sample records to the db manually
            self.cur.execute("INSERT INTO users (username, password, fullname, admin) VALUES ('bob.l', 'B0b!23', 'Bob Larson', 1)")
            self.cur.execute("INSERT INTO users (username, password, fullname, admin) VALUES ('ivy_russel', 'ivy@R123' , 'Ivy Russel', 0)")
            self.conn.commit()
        except: 
            None

    def login(self):
        username = input("please enter username: ").lower()
        password = input("please enter password: ")
        
        # string concatenation
        sql_statement = f"SELECT * from users WHERE username='{username}' AND password='{password}'"
        # sql_statement = f'SELECT * from users WHERE username="{username}" AND password="{password}"'
        
        self.cur.execute(sql_statement)

        loggedin_user = self.cur.fetchone()
        if not loggedin_user:  # An empty result evaluates to False.
            print("Login failed")
        else:
            self.loggedin = 1
            self.loggedin_user = username
            self.admin_is_loggedin = loggedin_user[3]
            user_type = 'Admin' if self.admin_is_loggedin == 1 else 'Not Admin'
            print('\n\n\n\nWelcome')
            heading = '▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄'  + '\n'   + \
                      '▍ '                                           + '\n'   + \
                      '▍ Username: ' + colored(self.loggedin_user, 'red')   + '\n'   + \
                      '▍ '                                           + '\n'   + \
                      '▍ User type: ' + colored(user_type, 'red')    + '\n'   + \
                      '▍ '                                           + '\n'   + \
                      '▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀'  + '\n'   + \
                      'User Menu'
            
            db_interface = user_interface(heading, db_menu)
            db_interface.run()
            del db_interface

    def show_all_clients(self):
        self.not_implemented(self.show_all_clients)

    def show_all_users(self):
        self.not_implemented(self.show_all_users)
    
    def add_new_client(self):
        self.not_implemented(self.add_new_client)
    
    def add_new_user(self):
        self.not_implemented(self.add_new_user)       

    def make_a_user_admin(self):
        self.not_implemented(self.make_a_user_admin)       

    def delete_client(self):
        self.not_implemented(self.delete_client)

    def delete_user(self):
        self.not_implemented(self.delete_user)

    def change_password(self):
        self.not_implemented(self.change_password)

    def logout(self):
        self.loggedin = 0
        self.loggedin_user = None
        self.admin_is_loggedin = 0

    def close(self):
        self.conn.close()

    def not_implemented(self, func):
        print(func.__name__ + ' method is Not implemented')
    
def escape_sql_meta(sql_query):
    pass

client = db(company_db_name, client_tb_name, users_tb_name,db_key)
main_menu = [[1, 'login', client.login ], [0, 'Exit', client.close]]
db_menu = [ [1, 'show all clients', client.show_all_clients], [2, 'show all users', client.show_all_users], \
            [3, 'add new client', client.add_new_client], [4, 'add new user', client.add_new_user], \
            [5, 'make a user "admin"', client.make_a_user_admin], \
            [6, 'delete a client', client.delete_client], [7, 'delete a user', client.delete_user], \
            [8, 'change password', client.change_password], [0, 'logout', client.logout]]