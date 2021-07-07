import sys

from pip._vendor.distlib.compat import raw_input
from ClientsDataManagementSystem.LoginUser import LoginUser
from ClientsDataManagementSystem.RegisterNewUser import RegisterNewUser


class CreateUserOrLogin:



    def tableEntries(self):
        question1 = raw_input('Hello \nWould you like to login or register? (plz answer with login or register) ')
        while(question1.lower().strip() != 'exit'):

            if(question1.lower().strip() == 'login'):
                LoginUser().login()
                question1 = raw_input('Would you like to login or register or exit? ')

            elif(question1.lower().strip() == 'register'):
                RegisterNewUser().registerUser()
                question1 = raw_input('Would you like to login or exit? ')

            else:
                print('That is not a valid input.')
                question1 = raw_input(
                    'Would you like to login or register? (plz answer with login or register ) enter exit if oyu want to exit ')




