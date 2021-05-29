import sqlite3
conn = sqlite3.connect('Lesson2.db')
cur = conn.cursor()
def is_admin(username: str) -> bool:
    cur.execute("""SELECT admin FROM users WHERE username = '%s' """ % username)
    # cur.executescript("""SELECT admin FROM users WHERE username = '%s' """ % username)
    result = cur.fetchone()
    conn.commit()
    conn.close()
    if result is None:
        # User does not exist
        return 0
    admin, = result
    return admin

# To test run those commands
# print(is_admin('ran'))
# print(is_admin('haki'))
# print(is_admin('foo'))
# print(is_admin("' Or 1=1;  --"))

# this example works in sqlite with excutescript(), comment line 5 and uncomment line 6
print(is_admin("'; update users set admin = '1' where username = 'haki'; --"))