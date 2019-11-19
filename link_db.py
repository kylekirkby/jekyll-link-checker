from sqlite3 import Error
import sqlite3
import os
from datetime import datetime


class LinkCheckerDB:
    def __init__(self, db_path=None):
        self._verbose = True
        # Store the db_path
        # If the db_path is not provided then a new database is created
        self.db_path = db_path
        # Set a default name for a new database
        self.db_name = "db.sqlite3"
        self.connection = self.connect_to_db()
        # Setup db with tables if they don't exist
        self.setup_db()

    def connect_to_db(self):
        """ Connect to the sqlite databse """
        # Check the db_path exists and is not None
        if self.db_path is None:
            self.db_path = "{0}/{1}".format(os.getcwd(), self.db_name)
        conn = None
        try:
            if self._verbose:
                print("Creating a new connection to {}".format(self.db_path))
            conn = sqlite3.connect(self.db_path)
            return conn
        except Error as e:
            print(e)

    def add_update_link(self, link):
        """
        Adds a link to the links table
        """
        # If the link exists then update the last_checked field
        check_query = ''' SELECT * FROM links WHERE link=?'''
        add_query = ''' INSERT INTO links(link,last_checked)
              VALUES(?,?) '''
        update_query = ''' INSERT INTO links(link,last_checked)
              VALUES(?,?) '''
        cursor = self.connection.cursor()
        cursor.execute(check_exists_query, (link,))
        results = cursor.fetchall()
        if results > 0:
            # Update timestamp
        else:
            # add link
            current_time = datetime.now()
            cursor.execute(sql_query, (link, current_time))

    def setup_db(self):
        """ Creates the required tables if they don't exist"""
        create_link_table = """
        CREATE TABLE IF NOT EXISTS links (
            id integer PRIMARY KEY,
            link text NOT NULL,
            last_checked NOT NULL
        );
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute(create_link_table)
            return True
        except Error as e:
            print(e)
            return False

    def query(self, sql_query):
        try:
            cursor = self.connection.cursor()
            cursor.execute(sql_query)
        except Error as e:
            print(e)
            return False

    def __del__(self):
        if self._verbose:
            print("Closing the open db connection to {}".format(self.db_path))
        # Close the currently open db connection.
        self.connection.close()


if __name__ == "__main__":
    print("Script running as __main__...")
    new_db = LinkCheckerDB()
    new_db.add_update_link("https://www.linaro.org")
