from sqlite3.dbapi2 import OperationalError

class user_interface:


    default_menu = [[1, 'option 1', None], [2, 'option 2', None], [3, 'option 2', None], [0, 'Exit', None]]

    def __init__(self, menuheading='Not logged in', menueitems = default_menu):
        self.menuheading = menuheading
        self.menuitems = menueitems
        self.menuoptions = [option[0] for option in self.menuitems]
        self.menufunctions = [option[2] for option in self.menuitems]

    def menu_display(self):
        print(self.menuheading)
        print('_________________________________\n')        
        for option in self.menuitems:
            print('[' + str(option[0]) + ']' + ' ' + option[1])
                
    def default_no_menuitems(self):
        print('Menu items are not defined')

    def run(self):
        self.menu_display()
        try:
            option = int(input('Choose a number from the menu: '))
            print()
        except:
            option = -1
            print()

        while option != self.menuoptions[-1]:
            if option in self.menuoptions:
                if self.menuitems == self.default_menu:
                    self.default_no_menuitems()
                else:
                    # try:
                    func_return = self.menuitems[self.menuoptions.index(option)][2]()
                    if func_return == 0:
                        option = 0
                        continue
                    # except:
                    #     print('Error!')
            else:
                print('invalid option')

            print()
            self.menu_display()
            try:
                option = int(input('Choose a number from the menu: '))
                print()
            except:
                option = -1
                print()
