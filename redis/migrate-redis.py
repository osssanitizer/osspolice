# -*- coding: utf-8 -*-

"""
Reference: https://gist.github.com/thomasst/afeda8fe80534a832607

Copies all keys from the source Redis host to the destination Redis host.
Useful to migrate Redis instances where commands like SLAVEOF and MIGRATE are
restricted (e.g. on Amazon ElastiCache).

The script scans through the keyspace of the given database number and uses
a pipeline of DUMP and RESTORE commands to migrate the keys.

Requires Redis 2.8.0 or higher.

Python requirements:
click==4.0
progressbar==2.3
redis==2.10.3
"""

import click
import logging
from progressbar import ProgressBar
from progressbar.widgets import Percentage, Bar, ETA
import redis
from redis.exceptions import ResponseError
from rediscluster import StrictRedisCluster
from ast import literal_eval

@click.command()
@click.argument('srchost')
@click.argument('dsthost')
@click.option('--srccluster', default=False, is_flag=True, help='source host is a cluster')
@click.option('--dstcluster', default=False, is_flag=True, help='destination host is a cluster')
@click.option('--db', default=0, help='Redis db number, default 0')
@click.option('--flush', default=False, is_flag=True, help='Delete all keys from destination before migrating')
def migrate(srchost, dsthost, srccluster, dstcluster, db, flush):
    if srchost == dsthost:
        print 'Source and destination must be different.'
        return

    if srccluster:
        source_nodes = literal_eval(srchost)
        source = StrictRedisCluster(startup_nodes=source_nodes, decode_responses=True)
        logging.debug('source cluster info: %s', source.cluster_info())
    else:
        source = redis.Redis(srchost, db=db)
    if dstcluster:
        dest_nodes = literal_eval(dsthost)
        dest = StrictRedisCluster(startup_nodes=dest_nodes, decode_responses=True)
        logging.debug('dest cluster info: %s', dest.cluster_info())
    else:
        dest = redis.Redis(dsthost, db=db)

    if flush:
        dest.flushdb()

    if srccluster:
        representatives = {v['cluster_my_epoch']: k for k, v in source.cluster_info().items()}
        size = source.dbsize()
        size = sum(size[reprensentative] for reprensentative in representatives.values())
    else:
        size = source.dbsize()

    if size == 0:
        print 'No keys found.'
        return

    progress_widgets = ['%d keys: ' % size, Percentage(), ' ', Bar(), ' ', ETA()]
    pbar = ProgressBar(widgets=progress_widgets, maxval=size).start()

    COUNT = 2000 # scan size

    cnt = 0
    non_existing = 0
    already_existing = 0
    cursor = 0

    if srccluster:
        counter = 0
        keys = []
        # iterate all the keys
        for key in source.scan_iter(count=COUNT):
            counter += 1
            keys.append(key)

            if counter % COUNT == 0:
                already_existing, non_existing = handle_keys(source, dest, keys, already_existing, non_existing)

                cnt += len(keys)
                pbar.update(min(size, cnt))
                keys = []

        # handle the remaining
        if len(keys) > 0:
            already_existing, non_existing = handle_keys(source, dest, keys, already_existing, non_existing)
            cnt += len(keys)
            pbar.update(min(size, cnt))

    else:
        while True:
            cursor, keys = source.scan(cursor, count=COUNT)
            already_existing, non_existing = handle_keys(source, dest, keys, already_existing, non_existing)

            if cursor == 0:
                break

            cnt += len(keys)
            pbar.update(min(size, cnt))

    pbar.finish()
    print 'Keys disappeared on source during scan:', non_existing
    print 'Keys already existing on destination:', already_existing


def handle_keys(source, dest, keys, already_existing, non_existing):
    pipeline = source.pipeline()
    for key in keys:
        pipeline.pttl(key)
        pipeline.dump(key)
    result = pipeline.execute()

    pipeline = dest.pipeline()

    for key, ttl, data in zip(keys, result[::2], result[1::2]):
        if ttl is None or ttl == -1:
            ttl = 0
        if data != None:
            pipeline.restore(key, ttl, data)
        else:
            non_existing += 1

    results = pipeline.execute(False)
    for key, result in zip(keys, results):
        if result != 'OK':
            e = result
            if hasattr(e, 'message') and (e.message == 'BUSYKEY Target key name already exists.' or e.message == 'Target key name is busy.'):
                already_existing += 1
            else:
                print 'Key failed:', key, `data`, `result`
                raise e
    logging.info("finished setting %d keys (already_exsiting %d)", len(keys), already_existing)
    return already_existing, non_existing


if __name__ == '__main__':
    """
    # migrate index database
    python migrate-redis.py --srccluster --dstcluster '[{"host": "sack.gtisc.gatech.edu", "port": "6408"}, {"host": "sack.gtisc.gatech.edu", "port": "6409"}]' '[{"host": "misfire.gtisc.gatech.edu", "port": "6000"}, {"host": "misfire.gtisc.gatech.edu", "port": "6001"}, {"host": "misfire.gtisc.gatech.edu", "port": "6002"}, {"host": "misfire.gtisc.gatech.edu", "port": "7000"}, {"host": "misfire.gtisc.gatech.edu", "port": "7001"}, {"host": "misfire.gtisc.gatech.edu", "port": "7002"}]'
    python migrate-redis.py --srccluster --dstcluster '[{"host": "sack.gtisc.gatech.edu", "port": "6404"}, {"host": "sack.gtisc.gatech.edu", "port": "6405"}]' '[{"host": "misfire.gtisc.gatech.edu", "port": "6000"}, {"host": "misfire.gtisc.gatech.edu", "port": "6001"}, {"host": "misfire.gtisc.gatech.edu", "port": "6002"}, {"host": "misfire.gtisc.gatech.edu", "port": "7000"}, {"host": "misfire.gtisc.gatech.edu", "port": "7001"}, {"host": "misfire.gtisc.gatech.edu", "port": "7002"}]'

    # migrate version database
    python migrate-redis.py --srccluster --dstcluster '[{"host": "sack.gtisc.gatech.edu", "port": "6410"}]' '[{"host": "misfire.gtisc.gatech.edu", "port": "6003"}, {"host": "misfire.gtisc.gatech.edu", "port": "6004"}, {"host": "misfire.gtisc.gatech.edu", "port": "6005"}, {"host": "misfire.gtisc.gatech.edu", "port": "7003"}, {"host": "misfire.gtisc.gatech.edu", "port": "7004"}, {"host": "misfire.gtisc.gatech.edu", "port": "7005"}]'
    python migrate-redis.py --srccluster --dstcluster '[{"host": "sack.gtisc.gatech.edu", "port": "6406"}]' '[{"host": "misfire.gtisc.gatech.edu", "port": "6003"}, {"host": "misfire.gtisc.gatech.edu", "port": "6004"}, {"host": "misfire.gtisc.gatech.edu", "port": "6005"}, {"host": "misfire.gtisc.gatech.edu", "port": "7003"}, {"host": "misfire.gtisc.gatech.edu", "port": "7004"}, {"host": "misfire.gtisc.gatech.edu", "port": "7005"}]'

    # no need to migrate result database
    """
    migrate()
