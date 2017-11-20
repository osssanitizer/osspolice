import binascii
import utils

###########################################################
# init state
###########################################################
redis = None
logger = None
stats_logger = None


###########################################################
# Indexed strings
###########################################################
def dump_repo_signatures():
    try:
        # register signal handler
        signal = utils.Signal()
        signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

        # iterate over all keys
        for key in redis.keys():

            # check for interruption
            if signal.caught():
                logger.error("Interrupted")
                return None

            # zset datatype for hashed strings
            if redis.type(key) == "zset":
                logger.info("%s,%s,", binascii.hexlify(key), redis.get(key))
            # elif redis.type(key) == "hset":
            else:
                print type(redis.type(key)), len(str(redis.type(key)))
                logger.info("%s -> %s,", key, redis.hgetall(key))

    except Exception as e:
        logger.error("Error dumping indexed strings %s", str(e))


def dump_tree(root, level, mapping, revmapping):
    indent = '|-' * (level)
    if root in revmapping:
        if root in mapping and len(mapping[root]) > 1:
            print('{}{} (match)'.format(indent, root))
        else:
            print('{}{}'.format(indent, root))
        # logger.info("{}{}".format(indent, root))
        for child in revmapping[root]:
            dump_tree(child, (level + 1), mapping, revmapping)


def dump_indexed_strings():
    try:
        # register signal handler
        signal = utils.Signal()
        signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

        # iterate over all keys
        mapping = {}
        revmapping = {}
        roots = []
        for key in redis.keys():

            # check for interruption
            if signal.caught():
                logger.error("Interrupted")
                return None

            # zset datatype for hashed strings
            if redis.type(key) == "zset":
                key = binascii.hexlify(key)
                values = redis.zrange(key, 0, -1, withscores=False)
                logger.info("%s,%s,", key, values)

            elif redis.type(key) == "set":
                values = redis.smembers(key)
                logger.info("%s -> %s", key, values)

            elif redis.type(key) == "hash" and '_' in key:
                values = redis.hgetall(key)
                logger.info("%s -> %s", key, values)

            elif (redis.type(key) == "hash" and '-' in key
                    and key.split('-', 1)[0] in ['str', 'func', 'file', 'dir', 'branch', 'repo']):
                values = redis.hgetall(key)
                logger.info("%s -> %s", key, values)
                from common import skip_set
                for h, c in values.items():
                    # skip special purpose item
                    if h in skip_set or h == key:
                        continue
                    if len(str(h)) < 10:
                        roots.append(h)
                    if not key in mapping:
                        mapping[key] = []
                    mapping[key].append(h)
                    if not h in revmapping:
                        revmapping[h] = []
                    if not key in revmapping[h]:
                        revmapping[h].append(key)

            elif not redis.type(key) == "hash" and len(str(key)) < 15:
                values = redis.get(key)
                logger.info("%s -> %s", key, values)

            # else:
            #    logger.info("%s type %s", key, redis.type(key))

        if revmapping and mapping:
            for root in roots:
                dump_tree(root, 0, mapping, revmapping)

    except Exception as e:
        logger.error("Error dumping indexed strings %s", str(e))


def dump_indexed_strings_freq_distribution():
    try:
        # register signal handler
        signal = utils.Signal()
        signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

        # iterate over all keys
        # for key in redis.keys():
        for key in redis.scan_iter():

            # check for interruption
            if signal.caught():
                logger.error("Interrupted")
                return None

            # zset datatype for hashed strings
            if redis.type(key) == "zset":
                logger.info("%s,%d,", binascii.hexlify(key), redis.zcard(key))

    except Exception as e:
        logger.error("Error dumping freq distribution of indexed strings %s", str(e))


def dump_indexed_unique_strings_repo_distribution():
    try:
        import matplotlib.pyplot as plt
        import numpy as np

        # register signal handler
        signal = utils.Signal()
        signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

        repo_all_strs = dict()
        repo_unq_strs = dict()

        # iterate over all keys
        for key in redis.keys():

            # check for interruption
            if signal.caught():
                logger.error("Interrupted")
                return None

            # zset datatype for hashed strings
            if redis.type(key) == "zset":
                for repo_id in redis.zrange(key, 0, -1, withscores=False):
                    if repo_id in repo_all_strs:
                        repo_all_strs[repo_id] += 1
                    else:
                        repo_all_strs[repo_id] = 1

                    if redis.zcard(key) == 1:
                        if repo_id in repo_unq_strs:
                            repo_unq_strs[repo_id] += 1
                        else:
                            repo_unq_strs[repo_id] = 1

        # format: repo_id, num_strs, num_uniq_strs, ratio_uniq_all_strs
        for repo_id, count in repo_all_strs.iteritems():
            try:
                ratio = float(repo_unq_strs[repo_id]) / count
                logger.info("%s,%d,%d,%0.2f", repo_id, count, \
                            repo_unq_strs[repo_id], ratio)
                repo_all_strs[repo_id] = ratio

            except Exception as e:
                logger.error("%s,%s", repo_id, str(e))

        plt.hist(repo_all_strs.values(), bins=50)  # np.logspace(1, 1000000, 100))
        plt.gca().set_xscale('log')
        plt.title("Unique/total strings across all repos")
        plt.xlabel('# Strings')
        plt.ylabel('# Repos')
        # pyplot.grid(True)
        plt.legend()
        plt.savefig('strings_hist', format='pdf')

    except ImportError as ie:
        logger.error("Error importing required modules: %s", str(e))

    except Exception as e:
        logger.error("Error dumping stats of indexed strings per repo %s", str(e))


def run(main, argv):
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger

    if len(argv) != 1:
        logger.error('expects only 1 arg')
        exit(1)

    arg = argv[0]
    print "Generating log %s" % (main.logger.handlers[1].baseFilename)

    response = raw_input("Which database do you want to dum java/native? [native]")
    if response.lower() == 'java':
        rc = main.jrc
    else:
        rc = main.nrc
    # make sure datastore is available and populated
    dbsize, values = rc.dbsize()
    if dbsize == 0:
        logger.error('nothing indexed!')
        exit(1)

    global redis
    redis = rc.handle()

    # choose
    if arg == 'strs':
        dump_indexed_strings()

    elif arg == 'strs-freq-dist':
        dump_indexed_strings_freq_distribution()

    elif arg == 'repo-signs':
        dump_repo_signatures()

    elif arg == 'repo-freq-dist':
        dump_indexed_unique_strings_repo_distribution()

    else:
        logger.error("invalid option: %s", argv)
