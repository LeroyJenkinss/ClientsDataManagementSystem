def select_all_users(conn):
    """
    Query all rows in the users table
    :param conn: the Connection object
    :return:
    """
    cur = conn.cursor()
    cur.execute("SELECT * FROM users")

    users = cur.fetchall()

    for user in users:
        print(user)