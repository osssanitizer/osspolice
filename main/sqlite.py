#!/usr/bin/env python

import sqlite3


###########################################################
# Database management
###########################################################
def enter_db(conn, repo_id, num_strs, logger=None):
    try:
        c = conn.cursor()
        c.execute('INSERT INTO {tn} VALUES({v1t}, {v2t}, {v3t}, {v4t})'. \
                  format(tn='repos', v1t=repo_id, v2t=num_strs, v3t=0, v4t=0))
        conn.commit()

    except Exception as e:
        logger.error("Error making db entry for repo %s: %s", repo_id, str(e))


def create_repo_db(logger=None):
    '''
    create database containing all repo ids
    '''
    conn = None
    try:
        conn = sqlite3.connect('repos.db')
        c = conn.cursor()

        # Creating a new SQLite table with 4 column
        c.execute('CREATE TABLE IF NOT EXISTS {tn} ' \
                  '({n1f} {f1t} PRIMARY KEY,' \
                  '{n2f} {f2t},' \
                  '{n3f} {f3t},' \
                  '{n4f} {f4t})' \
                  .format(tn='repos', \
                          n1f='ID', f1t='INTEGER', \
                          n2f='STRINGS', f2t='INTEGER', \
                          n3f='SYSCALLS', f3t='INTEGER', \
                          n4f='OBJECTS', f4t='INTEGER'))

        conn.commit()
        return conn

    except Exception as e:
        logger.error("Error creating database: %s", str(e))
        if conn:
            conn.close()
        return None
