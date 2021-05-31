from pip._vendor.distlib.compat import raw_input


class RegisterNewUser:

    def __init__(self):
        self.entryList = {'FullName': '', 'Address': '', 'ZipCode': '', 'City': '', 'EmailAddress': '',
                     'MobilePhone': ''}

    def registerUser(self):

        print('test 2')

        question1 = ''
        question2 = ''
        while(question1.lower().strip() != 'yes'):
            FullName = raw_input("Put in your FullName ")
            Address = raw_input("Put in your Address ")
            ZipCode = raw_input("Put in your ZipCode ")
            City = raw_input("Put in your City ")
            ZipCode = raw_input("Putin your ZipCode ")
            EmailAddress = raw_input("Put in your EmailAdress ")
            MobilePhone = raw_input("Put in your MobilePhone ")

            question1 = raw_input("Is the following correct\nFullname = "+FullName+'\nAddress = '+Address+'\nZipCode = '+ZipCode+'\nCity = '+City+'\nEmailAddress = '+EmailAddress+'\nMobilePhone\nPls answer with yes or no ')
            if(question1.lower().strip() == 'yes'):
                self.entryList["FullName"] = FullName
                self.entryList["Address"] = Address
                self.entryList["ZipCode"] = ZipCode
                self.entryList["City"] = City
                self.entryList["EmailAddress"] = EmailAddress
                self.entryList["MobilePhone"] = MobilePhone
            









