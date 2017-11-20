from redisclient import RedisClient
from config import Config
from random import shuffle
from time import time
from numpy import mean


class RedisPerf(object):
    def __init__(self, cluster_config_file, local_config_file, local_slave_config_file):
        # connect to the redis cluster as configured
        self.redis_cluster = RedisClient(Config(file_path=cluster_config_file), kind="JAVA").handle()
        # connect to local redis client
        try:
            self.redis_local = RedisClient(Config(file_path=local_config_file)).handle()
        except:
            print ("Run 'sudo docker run --name redis-local -p 6380:6379 -d redis' to create redis-local")
            self.redis_local = None
            raise
        # connect to redis client with slave as read-only
        try:
            self.redis_slave = RedisClient(Config(file_path=local_slave_config_file)).handle()
        except:
            print ("Run 'sudo docker run --name redis-slave -p 6381:6379 -d redis' to create redis-slave")
            self.redis_slave = None
            # raise

        # migrate to redis_local if it is empty
        if self.redis_local and len(self.redis_local.keys()) == 0:
            self.migrate_data(self.redis_cluster, self.redis_local)

        # migrate to redis_slave as well?
        # if self.redis_slave and len(self.redis_slave.keys()) == 0:
        #    self.migrate_data(self.redis_local, self.redis_slave)
        #    # other slave settings
        print ("cluster=%s\nlocal=%s\nlocal_slave=%s" % (
            sum(self.redis_cluster.dbsize().values()), self.redis_local.dbsize(), self.redis_slave.dbsize()))

    def smart_get(self, redis, key, key_type):
        if key_type == "list":
            return redis.lrange(key, 0, -1)
        elif key_type == "hash":
            return redis.hgetall(key)
        elif key_type == "set":
            return list(redis.sscan_iter(key))
        elif key_type == "zset":
            values = redis.zrange(key, 0, -1, withscores=True)
            values_list = []
            for k, v in values:
                values_list.append(v)
                values_list.append(k)
            return values_list
        elif key_type == "string":
            return redis.get(key)
        else:
            raise Exception("unhandled type: %s" % key_type)

    def smart_set(self, dst_redis, key, key_type, values):
        if key_type == "list":
            dst_redis.lpush(key, values)
        elif key_type == "hash":
            dst_redis.hmset(key, values)
        elif key_type == "set":
            dst_redis.sadd(key, values)
        elif key_type == "zset":
            dst_redis.zadd(key, *values)
        elif key_type == "string":
            dst_redis.set(key, values)
        else:
            raise Exception("unhandled type: %s" % key_type)

    def migrate_data(self, src_redis, dst_redis):
        count = 0
        for key in src_redis.keys():
            key_type = src_redis.type(key)
            values = self.smart_get(src_redis, key_type)
            self.smart_set(dst_redis, key_type, values)

    def perf_read(self, string_list, step=100):
        """
        - perf the redis read part
            - cluster with single get
            - local redis with single get
            - redis master-slave mode, slave as READ-ONLY

        :param string_list: the list of strings
        :param step: the number of string per step should increment, if len(string_list) = 1000, and step = 100, then
            the experiment will use number of strings from [100, 200, 300, ..., 1000] for perf. step can also be a list
            of predefined numbers, and can be useful for log-based step.
        :return:
        """
        len_string_list = len(string_list)
        if isinstance(step, int):
            steps = range(0, len_string_list, step)
            if steps[-1] != len_string_list:
                steps.append(len_string_list)
        elif isinstance(step, list):
            steps = [int(i) for i in step]
        else:
            raise Exception("Unexpected type for step: %s has type %s" % (step, type(step)))
        # maps each perf type, to {size: time_elapsed_list}
        perf_numbers = {"redis_cluster_sget": {}, "redis_local_sget": {}, "redis_slave_sget": {}}
        for size in steps:
            if size == 0:
                # This doesn't make sense
                for key, v in perf_numbers.items():
                    v[size] = []
                continue
            shuffle_num = len_string_list / size
            tmp_string_list = list(string_list)
            perf_numbers['redis_cluster_sget'].setdefault(size, [])
            perf_numbers['redis_local_sget'].setdefault(size, [])
            perf_numbers['redis_slave_sget'].setdefault(size, [])
            for index in range(shuffle_num):
                shuffle(tmp_string_list)
                use_tmp_string_list = tmp_string_list[:size]
                if self.redis_cluster:
                    # run cluster single get
                    t1 = time()
                    for s in use_tmp_string_list:
                        self.smart_get(self.redis_cluster, s, self.redis_cluster.type(s))
                    t2 = time()
                    perf_numbers['redis_cluster_sget'][size].append(t2 - t1)

                if self.redis_local:
                    # run local single get
                    t1 = time()
                    for s in use_tmp_string_list:
                        self.smart_get(self.redis_local, s, self.redis_cluster.type(s))
                    t2 = time()
                    perf_numbers['redis_local_sget'][size].append(t2 - t1)

                if self.redis_slave:
                    # run local slave single get
                    pass
                    # run local slave multiple get
                    pass
        for key, value in perf_numbers.items():
            print (key, {size: mean(t) for size, t in value.items() if t})

    def perf_write(self):
        """
        - perf the redis write part
            - only do local write?
            - pipeline all the requests
            - worker nodes do the computation, the master node processes strings, and inserts them into the database
        """
        pass

    def perf_pipe(self, n=1000):
        src_redis = self.redis_cluster
        keys = src_redis.keys()[:n]
        nonpipe_type_set = set()
        t1 = time()
        for key in keys:
            key_type = src_redis.type(key)
            nonpipe_type_set.add(key_type)
        t2 = time()
        pipe = src_redis.pipeline()
        for key in keys:
            pipe.type(key)
        values = pipe.execute()
        pipe_type_set = set(values)
        t3 = time()
        print ("string count %d" % len(keys))
        print ("non-pipeline took: %f, with result: %s" % (t2 - t1, nonpipe_type_set))
        print ("pipeline took: %f, with result: %s" % (t3 - t2, nonpipe_type_set))


if __name__ == "__main__":
    perf = RedisPerf(cluster_config_file="redis_perf_data/cluster_config",
                     local_config_file="redis_perf_data/local_config",
                     local_slave_config_file="redis_perf_data/local_slave_config")

    #########################################################
    # Perf pipeline
    # string count 5000
    # non-pipeline took: 3.264436, with result: set([u'hash', u'string', u'zset'])
    # pipeline took: 0.112474, with result: set([u'hash', u'string', u'zset'])
    # string count 50000
    # non-pipeline took: 32.852092, with result: set([u'hash', u'string', u'zset'])
    # pipeline took: 1.487891, with result: set([u'hash', u'string', u'zset'])
    #########################################################
    # perf.perf_pipe(n=5000)
    # perf.perf_pipe(n=50000)

    #########################################################
    # Perf read
    # cluster=870795
    # local=870795
    # ('redis_local_sget', {4000: 3.9767148494720459, 1000: 0.94302196502685542, 5000: 5.1367020606994629, 3000: 2.9924330711364746, 2000: 1.9413388967514038})
    # ('redis_cluster_sget', {4000: 5.9092020988464355, 1000: 1.4095116138458252, 5000: 7.3386409282684326, 3000: 4.3894889354705811, 2000: 2.7731920480728149})
    #########################################################
    strings = perf.redis_cluster.keys()
    shuffle(strings)
    strings = strings[:5000]
    perf.perf_read(string_list=strings, step=1000)

    # For write perf, we want to use another set of settings
    # perf.perf_write()
