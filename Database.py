import sqlite3

# Step 0 Data Preparation
# Create a database
connection = sqlite3.connect('ClientsDataManagment.db')
cur = connection.cursor()
# Create table
cur.execute('''CREATE TABLE users ( username varchar(30), admin boolean);''')

# Insert a row of data
cur.execute("INSERT INTO users (username, admin) VALUES ('ran', true),('haki', false);")

# Save (commit) the changes
connection.commit()

# We can also close the connection if we are done with it.
# Just be sure any changes have been committed or they will be lost.
connection.close()