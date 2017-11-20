import psycopg2
from itertools import izip
from ast import literal_eval


class PostgreSQL(object):
    def __init__(self, cfg, kind=None, logger=None):
        # Currently the postgresql only supports one table per database, and either JAVA or NATIVE db.
        self.__dbs = []
        self.__cons = []
        # default tables names to query
        self.__default_table_names = []
        self.__DB_HOST = None
        self.__DB_PORT = None

        self.debug = False
        self.logger = logger
        try:
            # get db host and port
            DB_HOST = cfg.get("DB_HOST", "PostgreSQL")
            if not DB_HOST:
                DB_HOST = 'localhost'
            self.__DB_HOST = DB_HOST
            DB_PORT = cfg.get("DB_PORT", "PostgreSQL")
            if not DB_PORT:
                DB_PORT = 5432
            else:
                DB_PORT = int(DB_PORT)
            self.__DB_PORT = DB_PORT

            # initialize the databases
            if kind.upper() == "JAVA":
                dbs = literal_eval(cfg.get("JAVA_DBS", "PostgreSQL"))
            else:
                dbs = literal_eval(cfg.get("NATIVE_DBS", "PostgreSQL"))
            self.__dbs = dbs
            for db in dbs:
                self.__cons.append(psycopg2.connect(database=db['database_name'], user=db['database_user'],
                                                    password=db['database_password'], host=DB_HOST, port=DB_PORT))
                self.__default_table_names.append(db['table_name'])
        except psycopg2.DatabaseError as e:
            help_msg = "If you are trying to connect to remote host, this may be caused by configurations on the " \
                       "remote host!\nYou need to modify /etc/postgresql/9.5/main/{postgresql.conf, pg_hba.conf} to " \
                       "listen for any incoming connections, and allow any incoming IPs!\n" \
                       "postgresql.conf\t---+--- listen_addresses = '*'\n" \
                       "pg_hba.conf\t---+--- host all all 0.0.0.0/0 trust\n"
            if logger:
                logger.info(help_msg)
                logger.error("Database error in postgres, Error: %s", str(e))

        except Exception as e:
            if logger:
                logger.error("Unhandled error in postgres: %s", str(e))

    def get_cons(self):
        for db in self.__dbs:
            yield psycopg2.connect(database=db['database_name'], user=db['database_user'],
                                   password=db['database_password'], host=self.__DB_HOST, port=self.__DB_PORT)

    def cursors(self):
        for con in self.get_cons():
            yield con.cursor()

    def cursor_tables(self):
        for con, table in izip(self.get_cons(), self.__default_table_names):
            yield con.cursor(), table

    def cursor_con_tables(self):
        for con, table in izip(self.get_cons(), self.__default_table_names):
            yield con.cursor(), con, table

    def __get_where_query(self, **filterargs):
        where_conditions = []
        v_list = []
        for k, v in filterargs.items():
            where_conditions.append('%s = %%s' % (str(k)))
            v_list.append(v)

        where_query = ' WHERE ' + ' AND '.join(where_conditions) if where_conditions else ''
        return (where_query, v_list)

    def __get_set_query(self, **setargs):
        set_pairs = []
        v_list = []
        for k, v in setargs.items():
            set_pairs.append('%s = %%s' % (str(k)))
            v_list.append(v)

        set_query = ' SET ' + ' , '.join(set_pairs) if set_pairs else ''
        return (set_query, v_list)

    def set_debug(self, debug):
        self.debug = debug

    def dbcount(self):
        return len(self.__cons)

    def dbsize(self, **filterargs):
        if not self.__cons:
            return None

        where_query, v_list = self.__get_where_query(**filterargs)
        results = []
        for cur, table in self.cursor_tables():
            if self.debug:
                table_select_query = "SELECT COUNT(*), current_database(), '%s' FROM %s" % (table, table) + where_query
            else:
                table_select_query = "SELECT COUNT(*) FROM %s" % (table) + where_query
            cur.execute(table_select_query, tuple(v_list))
            results.append(cur.fetchall()[0])  # dbsize is only one line
        return results

    def update(self, setmap, filtermap):
        """
        Update the databases with the setmap and filter map.

        :param setmap: the parameters to set
        :param filtermap: the conditions used to identify the rows to modify
        :return: sucess, True or False
        """
        # TODO: this is not tested yet
        set_query, set_v_list = self.__get_set_query(**setmap)
        where_query, where_v_list = self.__get_where_query(**filtermap)
        all_failed = True
        for cur, con, table in self.cursor_con_tables():
            try:
                table_update_query = 'UPDATE %s ' % (table) + set_query + where_query
                cur.execute(table_update_query, tuple(set_v_list + where_v_list))
                con.commit()
                all_failed = False
            except Exception as e:
                if self.logger:
                    self.logger.error("UPDATE error %s", str(e))
        if all_failed and self.logger:
            self.logger.error("UPDATE setmap = %s, filtermap = %, failed!", setmap, filtermap)
        return not all_failed

    def query(self, *selectargs, **filterargs):
        """
        Query the databases with the select args and filter args

        :param selectargs: select args
        :param filterargs: filter key, values
        :return: results, a list of fetchall results, where fetchall result is list of result tuples
            the results contains table and database information for debugging.
        """
        where_query, v_list = self.__get_where_query(**filterargs)
        results = []

        for cur, table in self.cursor_tables():
            if self.debug:
                table_select_query = "SELECT %s, current_database(), '%s' FROM %s" % (
                    ','.join(selectargs), table, table) + where_query
            else:
                table_select_query = "SELECT %s FROM %s" % (','.join(selectargs), table) + where_query
            cur.execute(table_select_query, tuple(v_list))
            results.append(cur.fetchall())
        return results

    def query_table(self, table_name, *selectargs, **filterargs):
        """Query the databases with the select args and filter args

        :param table_name: the table name to query
        :param selectargs: select args
        :param filterargs: filter key, values
        :return: results, a list of fetchall results, where fetchall result is list of result tuples
            the results contains table and database information for debugging.
        """
        where_query, v_list = self.__get_where_query(**filterargs)
        results = []

        for cur in self.cursors():
            if self.debug:
                table_select_query = "SELECT %s, current_database(), '%s' FROM %s" % (
                    ','.join(selectargs), table_name, table_name) + where_query
            else:
                table_select_query = "SELECT %s FROM %s" % (','.join(selectargs), table_name) + where_query
            cur.execute(table_select_query, tuple(v_list))
            results.append(cur.fetchall())
        return results

    def insert_table(self, table_name, insert_map):
        """Insert the insert map into the select specific table

        :param table_name: table to insert
        :param insert_map: the values to insert
        """
        keys = insert_map.keys()
        values = [insert_map[k] for k in keys]
        table_insert_query = "INSERT INTO %s (%s) VALUES (%s)" % (
            table_name, ','.join(keys), ','.join(['%s'] * len(keys)))
        try:
            for cur, con, _ in self.cursor_con_tables():
                cur.execute(table_insert_query, tuple(values))
                con.commit()
            return True
        except Exception as e:
            print ("Error inserting %s into table %s: %s" % (insert_map, table_name, str(e)))
