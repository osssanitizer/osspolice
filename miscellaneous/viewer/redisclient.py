#!/usr/bin/python

import config
import redis


###########################################################
# Redis Client
###########################################################
class RedisClient():
    __r = None
    __type = None

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

    def __init__(self, cfg, kind=None, logger=None):
        try:
            self.__type = cfg.get("TYPE", "Redis")
            self.__db = cfg.get("DATABASE", 0)
            if not self.__type:
                self.__r = redis.StrictRedis(host='localhost', port=6379, db=self.__db)
                self.__type = 'TCP_SOCKET'

            if self.__type == "UNIX_DOMAIN":
                self.__r = redis.Redis(unix_socket_path='/tmp/redis.sock', db=self.__db)

            elif self.__type == "REDIS_CLUSTER":
                from rediscluster import StrictRedisCluster
                import json
                if kind.upper() == "JAVA":
                    nodes = json.loads(cfg.get("JAVA_NODES", "RedisCluster"))
                elif kind.upper() == "NATIVE":
                    nodes = json.loads(cfg.get("NATIVE_NODES", "RedisCluster"))
                elif kind.upper() == "RESULT":
                    nodes = json.loads(cfg.get("RESULT_NODES", "RedisCluster"))
                else:
                    logger.error("Unknown kind of REDIS_CLUSTER: %s", kind)
                self.__r = StrictRedisCluster(startup_nodes=nodes, decode_responses=True)

            elif self.__type == "TCP_SOCKET":
                port = cfg.get("PORT", "Redis")
                host = cfg.get("HOST", "Redis")
                self.__r = redis.StrictRedis(host=host, port=port, db=self.__db)

            else:
                if logger:
                    logger.error("Invalid redis cfg type %s", self.__type)
                print("Invalid redis cfg type %s" % (self.__type))
                return None

            # check if Redis server is available
            response = self.__r.client_list()

        except (redis.exceptions.ConnectionError,
                redis.exceptions.BusyLoadingError):
            if logger:
                logger.error("Redis connection error")
            print("Redis connection error")
            return None

        except ImportError as e:
            if logger:
                logger.error("Redis module not available. Please install.")
            print("Redis module not available. Please install.")
            return None
