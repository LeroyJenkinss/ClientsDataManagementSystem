from datetime import datetime
from time import localtime, strftime
import Database
import EncryptingDb

class logging:


    def __init__(self,username, date, time, description_of_activity, additionalInfo, supicious):
        self.username =  self.encrypt(username)
        self.date = self.encrypt(datetime.strftime('%Y-%m-%d'))
        self.time = self.encrypt(strftime("%H:%M:%S", localtime()))
        self.description_of_activity = self.encrypt(description_of_activity)
        self.additionalInfo = self(additionalInfo)
        self.supicious = self(supicious)

        Database.db().insertLoggingInDB(self.username,self.date,self.time,self.description_of_activity,self.additionalInfo,self.supicious)




    def encrypt(self,value):
        return EncryptingDb.EncryptingDb().encrypt(value)












