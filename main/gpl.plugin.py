#!/usr/bin/python -u
# use -u at shebang to disable buffering
# http://stackoverflow.com/questions/107705/disable-output-buffering

import sys, errno, time, random, argparse
import redis


#################################################################
# Configuration parser
#################################################################
class Config(object):
    __configParser = None

    def __init__(self, file_path="config"):
        try:
            import ConfigParser
            self.__configParser = ConfigParser.RawConfigParser()
            self.__configParser.read(file_path)

        except ImportError as ie:
            raise Exception("ConfigParser module not available. Please install")

        except Exception as e:
            raise Exception("Error parsing " + file_path + ": " + str(e))

    def get(self, opt, sec="Main"):
        if not self.__configParser:
            return None
        try:
            return self.__configParser.get(sec, opt)
        except Exception as e:
            # raise Exception("Error getting config for " + \
            #                    sec + " :" + cfg + ": " + str(e))
            return None


###########################################################
# Redis Client
###########################################################
class RedisClient():
    __r = None
    __type = None

    def handle(self):
        return self.__r

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
                from ast import literal_eval
                if kind.upper() == "JAVA":
                    nodes = literal_eval(cfg.get("JAVA_NODES", "RedisCluster"))
                elif kind.upper() == "NATIVE":
                    nodes = literal_eval(cfg.get("NATIVE_NODES", "RedisCluster"))
                elif kind.upper() == "RESULT":
                    nodes = literal_eval(cfg.get("RESULT_NODES", "RedisCluster"))
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


sys.stdin.close()

config = Config('/home/gplviolation/run-docker/celery-worker/config.java')
rc_native = RedisClient(config, 'native')
rc_java = RedisClient(config, 'java')
if not rc_native or not rc_java:
    exit(1)

parser = argparse.ArgumentParser(description='plugin to monitoring repo indexing')
parser.add_argument('update_every', type=int, nargs='?', help='update frequency in seconds')
args = parser.parse_args()

# internal defaults for the command line arguments
update_every = 1

# evaluate the command line arguments
if args.update_every != None:
    update_every = args.update_every

# various preparations
update_every *= 1000
get_millis = lambda: int(round(time.time() * 1000))

# generate the charts
try:
    # CHART type.id name title units [family [context [charttype [priority [update_every]]]]]
    # DIMENSION id [name [algorithm [multiplier [divisor [hidden]]]]]
    sys.stdout.write(
        'CHART GPLPolice.NativeIndexing NativeRepos "Native Indexing Stats" "Repos" "Indexing" "Native" line 100000 %s\n' % int(
            update_every / 1000))
    sys.stdout.write('DIMENSION size "DB Size" absolute 1 1\n')
    sys.stdout.write('DIMENSION mem "Memory Used" absolute 1 1\n')
    sys.stdout.write('DIMENSION count "Repo Count" absolute 1 1\n')

    sys.stdout.write(
        'CHART GPLPolice.JavaIndexing JavaArchives "Java Indexing Stats" "Repos" "Indexing" "Java" line 100000 %s\n' % int(
            update_every / 1000))
    sys.stdout.write('DIMENSION size "DB Size" absolute 1 1\n')
    sys.stdout.write('DIMENSION mem "Memory Used" absolute 1 1\n')
    sys.stdout.write('DIMENSION count "Repo Count" absolute 1 1\n')

    sys.stdout.flush()
except IOError as e:
    sys.stderr.write('Failed to send data to netdata\n')
    sys.exit(0)

# the main loop
count = 0
last_run = next_run = now = get_millis()
while True:
    if next_run <= now:
        count += 1

        # DO DATA COLLECTION HERE
        value1 = random.randint(0, 1000)

        # debugging to know it is working
        # stderr is going to /var/log/netdata/error.log
        # don't enable on production
        # sys.stderr.write('collecting data, iteration No %s\n' % count)
        # sys.stderr.flush()

        # get the current time again
        # data collection may be too slow
        now = get_millis()

        # find the time for the next run
        while next_run <= now:
            next_run += update_every

        # calculate dt = the time we took
        # since the last run
        dt = now - last_run
        last_run = now

        # on the first iteration, don't set dt
        # allowing netdata to align itself
        if count == 1:
            dt = 0

        # send the values to netdata
        try:
            sys.stdout.write('BEGIN GPLPolice.NativeIndexing %s\n' % (dt * 1000))
            val = rc_native.dbsize()[0]
            if not val: val = 0
            sys.stdout.write('SET size = %s\n' % str(val))
            val = rc_native.memused()[0]
            if not val: val = 0
            sys.stdout.write('SET mem = %s\n' % str(val))
            val = rc_native.handle().get("repos")
            if not val: val = 0
            sys.stdout.write('SET count = %s\n' % str(val))
            sys.stdout.write('END\n')

            sys.stdout.write('BEGIN GPLPolice.JavaIndexing %s\n' % (dt * 1000))
            val = rc_java.dbsize()[0]
            if not val: val = 0
            sys.stdout.write('SET size = %s\n' % str(val))
            val = rc_java.memused()[0]
            if not val: val = 0
            sys.stdout.write('SET mem = %s\n' % str(val))
            val = rc_java.handle().get("reposcnt")
            if not val: val = 0
            sys.stdout.write('SET count = %s\n' % str(val))
            sys.stdout.write('END\n')

            sys.stdout.flush()
        except IOError as e:
            sys.stderr.write('Failed to send data to netdata\n')
            sys.exit(0)

    # sleep 1/10 of update_every
    time.sleep(update_every / 1000 / 10)
    now = get_millis()
