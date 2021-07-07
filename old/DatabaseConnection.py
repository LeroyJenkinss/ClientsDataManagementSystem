# imports
import sqlite3

class DatabasConnection:
    conn = sqlite3.connect('ClientsDataManagment.db')
    cur = conn.cursor()
    print('sdfg')



    def is_admin(self, username: str) -> bool:
        self.cur.executescript("""SELECT admin FROM users WHERE username = '%s' """ % username)

        # cur.executescript("""SELECT admin FROM users WHERE username = '%s' """ % username)
        result = self.cur.fetchone()
        self.conn.commit()
        self.conn.close()
        if result is None:
            # User does not exist
            return 0
        admin, = result
        return admin


    print(is_admin("'; update users set admin = '1' where username = 'haki'; --"))