import sqlite3

# Step 0 Data Preparation
# Create a database
connection = sqlite3.connect('ClientsDataManagment.db')
cur = connection.cursor()
# Create table
cur.execute('''CREATE TABLE clients ( FullName varchar(30),Address varchar(40),ZipCode varchar(6),City varchar(40),EmailAddress varchar(30),MobilePhone integer(10));''')
cur.execute('''CREATE TABLE users ( UserName varchar(30),Password varchar(40), type varchar(30));''')
# Insert a row of data
cur.execute("INSERT INTO users ( UserName, Password, type) VALUES ('master', 'password', 'SuperAdmin');")

# Save (commit) the changes
connection.commit()

# We can also close the connection if we are done with it.
# Just be sure any changes have been committed or they will be lost.
connection.close()