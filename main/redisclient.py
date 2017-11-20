#!/usr/bin/python

import config
import redis


###########################################################
# Redis Client
###########################################################
class RedisClient(object):
    __r = None
    __type = None
    __specified = False
    __port = 6379
    __host = 'localhost'

    def specified(self):
        return self.__specified

    def handle(self):
        return self.__r

    def pipeline(self, transaction=False):
        return self.__r.pipeline(transaction=transaction)

    def memused(self):
        if not self.__r:
            return None
        try:
            mem = []
            if self.__type == "TCP_SOCKET" or self.__type == "UNIX_DOMAIN":
                mem.append(self.__r.info()['used_memory'])
            elif self.__type == "REDIS_CLUSTER":
                for key, value in self.__r.info().iteritems():
                    mem.append(value['used_memory'])
            return sum(mem), mem
        except Exception as e:
            raise Exception("Error dumping memory info: " + str(e))

    def dbsize(self):
        if not self.__r:
            return None
        try:
            keys = []
            if self.__type == "TCP_SOCKET" or self.__type == "UNIX_DOMAIN":
                keys.append(self.__r.dbsize())
            elif self.__type == "REDIS_CLUSTER":
                keys = self.__r.dbsize().values()
            return sum(keys), keys
        except Exception as e:
            raise Exception("Error dumping index size: " + str(e))

    def flush(self):
        try:
            if self.__r:
                self.__r.flushall()
                self.__r.flushdb()
        except Exception as e:
            raise Exception("Error flushing: " + str(e))

    def __init__(self, cfg, kind=None, logger=None, readonly=False):
        try:
            self.__type = cfg.get("TYPE", "Redis")
            self.__db = cfg.get("DATABASE", 0)
            if not self.__type:
                self.__specified = True
                self.__r = redis.StrictRedis(host=self.__host, port=self.__port, db=self.__db)
                self.__type = 'TCP_SOCKET'

            if self.__type == "UNIX_DOMAIN":
                self.__specified = True
                self.__r = redis.Redis(unix_socket_path='/tmp/redis.sock', db=self.__db)

            elif self.__type == "REDIS_CLUSTER":
                from rediscluster import StrictRedisCluster
                from ast import literal_eval
                nodes = None
                if kind.upper() == "JAVA":
                    val = cfg.get("JAVA_NODES", "RedisCluster")
                    if val:
                        nodes = literal_eval(val)
                elif kind.upper() == "NATIVE":
                    val = cfg.get("NATIVE_NODES", "RedisCluster")
                    if val:
                        nodes = literal_eval(val)
                elif kind.upper() == "JAVA_VERSION":
                    val = cfg.get("JAVA_VERSION_NODES", "RedisCluster")
                    if val:
                        nodes = literal_eval(val)
                elif kind.upper() == "NATIVE_VERSION":
                    val = cfg.get("NATIVE_VERSION_NODES", "RedisCluster")
                    if val:
                        nodes = literal_eval(val)
                elif kind.upper() == "RESULT":
                    val = cfg.get("RESULT_NODES", "RedisCluster")
                    if val:
                        nodes = literal_eval(val)
                else:
                    logger.error("Unknown kind of REDIS_CLUSTER: %s", kind)
                if nodes:
                    self.__specified = True
                    self.__r = StrictRedisCluster(startup_nodes=nodes, decode_responses=True, readonly_mode=readonly)
                else:
                    raise Exception("Redis kind %s not specified!" % kind)

            elif self.__type == "TCP_SOCKET":
                self.__host = cfg.get("HOST", "Redis")
                self.__port = cfg.get("PORT", "Redis")
                self.__specified = True
                self.__r = redis.StrictRedis(host=self.__host, port=self.__port, db=self.__db)

            else:
                if logger:
                    logger.error("Invalid redis cfg type %s", self.__type)
                print("Invalid redis cfg type %s" % self.__type)

            # check if Redis server is available
            response = self.__r.client_list()

        except (redis.exceptions.ConnectionError,
                redis.exceptions.BusyLoadingError):
            if logger:
                logger.error("Redis connection error")
            print("Redis connection error")

        except ImportError as ie:
            if logger:
                logger.error("Redis module not available. Please install. Error: %s", str(ie))
            print("Redis module not available. Please install.")

        except Exception as e:
            if logger:
                logger.error("Error getting kind %s from config: %s!", kind, str(e))
            print("Kind %s doesn't exist in config. Error %s." % (kind, str(e)))
