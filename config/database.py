import psycopg2
from dotenv import load_dotenv
import os

load_dotenv()

database_url = os.getenv("DATABASE_URL")
db_password = os.getenv("DB_PASSWORD")
class DataBase():
    def __init__(self):
        try:
            self.db = psycopg2.connect(
                host = database_url,
                port = 5432,
                user = "postgres",
                password = db_password,
                dbname = "banking_system"
            )
            self.db.autocommit = False
            print("DataBase Connection Sucessful")
        except psycopg2.Error as e:
            print("Database Conncetion error:", e)
            self.db = None
    def get_cursor(self):
        try:
            if self.db and self.db.closed:
                self.__init__()
            return self.db.cursor()
        except Exception as e:
            print("Could not connect to database:", e)
            return None       
