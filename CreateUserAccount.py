import sys

from pip._vendor.distlib.compat import raw_input
from ClientsDataManagementSystem.LoginUser import LoginUser
from ClientsDataManagementSystem.RegisterNewUser import RegisterNewUser


class CreateUserAccount:



    def tableEntries(self):
        question1 = raw_input('Hello \nWould you like to login or register? (plz answer with login or register )')
        if(question1.lower().strip() == 'login'):
            LoginUser().login()

        elif(question1.lower().strip() == 'register'):
            RegisterNewUser().registerUser()


