from pip._vendor.distlib.compat import raw_input

class LoginUser:

    def login(self):

        i = 0
        while i < 3:
            username = raw_input("Put in your Username ")
            password = raw_input("Put in your Password ")
            find_user = ("SELECT * FROM users WHERE UserName = username AND Password = password")
            if len(find_user) < 1:
                return find_user
            else:
                i = i+1

        print('To many wrong attempts')
