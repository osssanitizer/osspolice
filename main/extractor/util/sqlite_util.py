import sqlite3
import os
import logging
from time import sleep
from random import randint

try:
    from itertools import izip as zip
except ImportError:
    pass

"""Manages access to the database specified by dbpath.

This class supports the following database operations:
1. create table
2. insert row
3. insert multirow
4. update row
5. exists row
6. select row
# TO ADD.
"""
class SQLiteDatabase(object):
    filename = ''
    conn = None
    MIN_SLEEP = 1
    MAX_SLEEP = 5

    def __init__(self, dbpath):
        self.filename = dbpath
        if os.path.exists(self.filename):
            self.conn = sqlite3.connect(self.filename)
        else:
            self.conn = None

    def has_connection(self):
        return self.conn is not None

    def create_table(self, table_name, column_type_dict):
        self.conn = sqlite3.connect(self.filename)
        cursor = self.conn.cursor()
        try:
            cursor.execute(generate_create_sqlstr(table_name=table_name, column_type_dict=column_type_dict))
            self.conn.commit()
            cursor.execute("PRAGMA journal_mode=WAL;")  # Faster, concurrent access
            self.conn.commit()
        except:
            raise

    def insert_table_multirow(self, table_name, column_name_list, column_value_lists, max_per_query=5000,
                              max_retries=5):
        assert isinstance(column_name_list, list)
        # To save memory, make column_value_lists a generator
        cursor = self.conn.cursor()
        toinsert_lists = []
        try:
            for column_value_list in column_value_lists:
                toinsert_lists.append(column_value_list)
                # If the insertion number has reached the predefined threshold, insert them, and reset toinsert list.
                if len(toinsert_lists) == max_per_query:
                    msg = "process the reached max_per_query(%d) limit" % max_per_query
                    logging.debug(msg)
                    print (msg)
                    sqlstr, value_tuple_list = generate_insert_sqlstr_multivalue_tuple(
                        table_name=table_name, column_name_list=column_name_list, column_value_lists=toinsert_lists)
                    toinsert_lists = []
                    cursor.executemany(sqlstr, value_tuple_list)
                    self.conn.commit()

            # If the insertion is not finished
            if len(toinsert_lists) > 0:
                msg = "process the remaining %d row insertions" % len(toinsert_lists)
                logging.debug(msg)
                print (msg)
                sqlstr, value_tuple_list = generate_insert_sqlstr_multivalue_tuple(
                    table_name=table_name, column_name_list=column_name_list, column_value_lists=toinsert_lists)
                cursor.executemany(sqlstr, value_tuple_list)
                self.conn.commit()
        except sqlite3.IntegrityError:
            logging.error("Duplicated")
            print ("Duplicated")
        except sqlite3.OperationalError:
            remaining_retries = max_retries - 1
            if remaining_retries > 0:
                sleep(randint(self.MIN_SLEEP, self.MAX_SLEEP))
                logging.error("database is locked, retrying...")
                print ("Retrying")
                self.insert_table_multirow(table_name=table_name, column_name_list=column_name_list,
                                           column_value_lists=column_value_lists, max_per_query=max_per_query,
                                           max_retries=remaining_retries)
            else:
                logging.error("database is locked, max-retry reached")
                raise

    def insert_table(self, table_name, column_name_value_dict, max_retries=5):
        sqlstr, value_tuple = generate_insert_sqlstr_value_tuple(table_name=table_name, item=column_name_value_dict)
        cursor = self.conn.cursor()
        try:
            cursor.execute(sqlstr, value_tuple)
            self.conn.commit()
        except sqlite3.IntegrityError:
            logging.error("Duplicated")
            print ("Duplicated")
        except sqlite3.OperationalError:
            remaining_retries = max_retries - 1
            if remaining_retries > 0:
                sleep(randint(self.MIN_SLEEP, self.MAX_SLEEP))
                logging.error("database is locked, retrying...")
                print ("Retrying: %s, %s" % (sqlstr, value_tuple))
                self.insert_table(table_name=table_name, column_name_value_dict=column_name_value_dict,
                                  max_retries=remaining_retries)
            else:
                logging.error("database is locked, max-retry reached")
                raise

    def update_table(self, table_name, set_name_value_dict, where_name_value_dict, max_retries=5):
        # This is not single process and multi-thread program, so we are not using threading locks.
        sqlstr, value_tuple = generate_update_sqlstr_value_tuple(
            table_name=table_name, set_name_value_dict=set_name_value_dict,
            where_name_value_dict=where_name_value_dict)
        cursor = self.conn.cursor()
        try:
            cursor.execute(sqlstr, value_tuple)
            self.conn.commit()
        except sqlite3.IntegrityError:
            logging.error("Update Error")
            print ("Update Error")
        except sqlite3.OperationalError:
            remaining_retries = max_retries - 1
            if remaining_retries > 0:
                sleep(randint(self.MIN_SLEEP, self.MAX_SLEEP))
                logging.error("database is locked, retrying...")
                print ("Retrying: %s, %s" % (sqlstr, value_tuple))
                self.update_table(table_name=table_name, set_name_value_dict=set_name_value_dict,
                                  where_name_value_dict=where_name_value_dict, max_retries=remaining_retries)
            else:
                logging.error("database is locked, max-retry reached")
                raise

    def exists_table(self, table_name, where_name_value_dict):
        sqlstr, value_tuple = generate_exists_sqlstr_value_tuple(table_name=table_name,
                                                                 where_name_value_dict=where_name_value_dict)
        cursor = self.conn.cursor()
        cursor.execute(sqlstr, value_tuple)
        return True if cursor.fetchone()[0] else False

    def query_table(self, table_name, select_name_list, where_name_value_dict, fetchone=False):
        assert isinstance(select_name_list, list)
        sqlstr, value_tuple = generate_select_sqlstr_value_tuple(
            table_name=table_name, select_name_list=select_name_list, where_name_value_dict=where_name_value_dict)
        cursor = self.conn.cursor()
        if value_tuple:
            cursor.execute(sqlstr, value_tuple)
        else:
            cursor.execute(sqlstr)
        if fetchone:
            return cursor.fetchone()
        else:
            return cursor.fetchall()

    def disconnect(self):
        if self.conn is not None:
            self.conn.commit()
            self.conn.close()
            self.conn = None


"""
Utility functions for generating sql strings. This seems universal, it can be extended to generate strings for all
kinds of databases, e.g. sqlite, postgres, mongodb.
"""
def generate_create_sqlstr(table_name, column_type_dict):
    # Formulate the sql string and value tuple for sql create queries
    # Foreign key creation should be at the end of statement.
    # Constraint key should be at the end of statement as well.
    # http://stackoverflow.com/questions/13787443/syntax-error-with-foreign-key-in-create-table
    column_list = []
    type_list = []
    nondef_col_type_dict = {}
    for key, value in column_type_dict.items():
        if 'foreign' in key.lower() or 'constraint' in key.lower():
            nondef_col_type_dict[key] = value
        else:
            column_list.append(key)
            type_list.append(value)
    for key, value in nondef_col_type_dict.items():
        column_list.append(key)
        type_list.append(value)
    sqlstr = 'CREATE TABLE %s(%s)' % (
        table_name, ', '.join(['%s %s' % (column, type) for column, type in zip(column_list, type_list)]))
    logging.debug(sqlstr)
    return sqlstr


def generate_exists_sqlstr_value_tuple(table_name, where_name_value_dict):
    key_list = []
    value_list = []
    for key, value in where_name_value_dict.items():
        key_list.append('%s = ?' % key)
        value_list.append(value)

    sqlstr = 'SELECT EXISTS (SELECT * FROM %s WHERE %s)' % (table_name, ' AND '.join(key_list))  # Ends the inner select
    return (sqlstr, tuple(value_list))


def generate_select_sqlstr_value_tuple(table_name, select_name_list, where_name_value_dict):
    # Formulate the sql string and value tuple for sql update queries
    if where_name_value_dict:
        key_list = []
        value_list = []
        for key, value in where_name_value_dict.items():
            key_list.append('%s = ?' % key)
            value_list.append(value)
        sqlstr = 'SELECT (%s) FROM %s WHERE %s' % (','.join(select_name_list), table_name, ' AND '.join(key_list))
    else:
        sqlstr = 'SELECT (%s) FROM %s' % (','.join(select_name_list), table_name)
        value_list = []
    return (sqlstr, tuple(value_list))


def generate_update_sqlstr_value_tuple(table_name, set_name_value_dict, where_name_value_dict):
    # Formulate the sql string and value tuple for sql update queries
    sqlstr = 'UPDATE %s SET ' % table_name
    value_list = []
    tmp_key_list = []
    for key, value in set_name_value_dict.items():
        tmp_key_list.append('%s = ?' % key)
        value_list.append(value)
    set_name_str = ', '.join(tmp_key_list)
    sqlstr += set_name_str + ' WHERE '
    tmp_key_list = []
    for key, value in where_name_value_dict.items():
        tmp_key_list.append('%s = ?' % key)
        value_list.append(value)
    select_name_str = ' AND '.join(tmp_key_list)
    sqlstr += select_name_str
    return (sqlstr, tuple(value_list))


def generate_insert_sqlstr_multivalue_tuple(table_name, column_name_list, column_value_lists):
    # Formulate the sql string and value tuple for batch sql insert queries
    # The key point is to use executemany function
    # https://docs.python.org/2/library/sqlite3.html
    sqlstr = 'INSERT INTO %s( %s ) VALUES ( %s )' % (table_name, ','.join(column_name_list),
                                                     ','.join(['?'] * len(column_name_list)))
    return (sqlstr, column_value_lists)


def generate_insert_sqlstr_value_tuple(table_name, item, special_key_callbacks=None, reference_item_key=None,
                                       reference_item=None):
    # Formulate the sql string and value tuple for sql insert queries
    sqlstr = 'INSERT INTO %s(' % table_name
    key_list = []
    value_list = []
    if reference_item_key and reference_item:
        key_list.append(reference_item_key)
        value_list.append(reference_item.get(reference_item_key, None))
    for key in item.keys():
        if special_key_callbacks and (key in special_key_callbacks):
            # TODO: Is this needed?
            # special_key_callbacks should be a dict
            if special_key_callbacks[key]:
                special_value = special_key_callbacks[key](item.get(key, None))
                if special_value:
                    key_list.append(key)
                    value_list.append(special_value)
        elif item.get(key, None):
            key_list.append(key)
            value_list.append(item.get(key, None))
    sqlstr += '%s) VALUES (%s)' % (','.join(key_list), ','.join(['?'] * len(key_list)))
    return (sqlstr, tuple(value_list))
