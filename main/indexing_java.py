import os
import sys
import shutil
import tempfile
import time
import random
import operator
import json
import rediscluster
from itertools import chain
from collections import Counter
from os.path import join, basename, splitext

import utils
import signature_java
from version_db import build_version_db
from utils import get_simhash_distance, get_node_id
from common import get_typed_key, get_untyped_key, get_rtyped_key, get_rkey, get_feature_count_name
from centroid import get_centroid_string, build_centroid_db
from signature_java import (get_input_list, get_all_classes_summary, get_input_id,
                            get_no_package_func, get_obfuscation_resilient_func, get_class_string)
from signature_java_constants import (JOB_CHUNK, framework_prefix, skip_set)

###########################################################
# init state
###########################################################
logger = None
stats_logger = None


###########################################################
# Build database
###########################################################
def get_node_path(input_path, package_name, class_name):
    return join(input_path, join(package_name.replace('.', '/'), class_name))


def get_software_details(main, input_path):
    # NOTE: the software details are queried against two databases (jcenter and maven), if any of the db returns result,
    # we should take it and break!

    # set the software_id, and version
    downloaded_path, version, filename = input_path.rsplit('/', 2)
    software_id = artifact_id = group_id = license_abbrs = cve2cpe = None
    cve_count = 0

    logger.info("Set the software id information for Repo %s", input_path)
    # 1. Try downloaded_path first, which is basename of the downloaded repository. But database may not be available!
    logger.info(
        "Try downloaded_path first, which is basename of the downloaded repository. But database may not be available!")
    for r in main.jdb.query("lib_id", "artifact_id", "group_id", downloaded_path=basename(downloaded_path)):
        if r:
            software_id, artifact_id, group_id = r[0][0:3]
            break
    # 2. Guess the artifact name and version from the filename.
    if not software_id:
        logger.info("Guess the artifact name and version from the filename.")
        try:
            artifact_id, version = splitext(filename)[0].rsplit('-', 1)
            for r in main.jdb.query("lib_id", "artifact_id", "group_id", artifact_id=artifact_id):
                logger.error('query: %s', r)
                if r:
                    logger.error('found: %s', r)
                    software_id, artifact_id, group_id = r[0][0:3]
                    break
        except Exception as e:
            logger.error("failed to get software_id information for %s, error %s, Ignoring!", downloaded_path, str(e))

    # 3. Get the license for this particular version, based on lib_id
    if software_id and version:
        logger.info("Get the license for this particular version, based on lib_id")
        # license information
        try:
            for r in main.jdb.query_table("lib_licenses", "lib_id", "version_number", "abbrs", lib_id=software_id,
                                          version_number=version):
                if r:
                    _, _, license_abbrs = r[0][0:3]
                    break
        except Exception as e:
            logger.error("failed to get license information for %s, error %s", downloaded_path, str(e))

    # 4. Get the vulnerability information for this particular version, based on lib_id
    if software_id:
        logger.info("Get the vulnerability information for this particular version, based on lib_id")
        # vulnerability information
        try:
            for r in main.jdb.query_table("lib_versions", "lib_id", "version_number", "cve2cpe", "cve_count",
                                          lib_id=software_id, version_number=version):
                if r:
                    _, _, cve2cpe, cve_count = r[0][0:4]
                    if cve_count and int(cve_count) > 0:
                        cve_count = int(cve_count)
                        cve2cpe = json.loads(cve2cpe)
                    else:
                        cve_count = 0
                        cve2cpe = {}
                    break
        except Exception as e:
            logger.error("failed to get vulnerability information for %s, error %s", downloaded_path, str(e))

    return {'software_id': software_id, 'artifact_id': artifact_id, 'group_id': group_id, 'version': version,
            'license': license_abbrs, 'cve_count': cve_count, 'cve2cpe': cve2cpe}


def build_db(main, input_path, input_type, outdir):
    java_hash = 0
    num_java_indexing_keys = 0
    num_strs = 0
    num_classes = 0
    num_normclasses = 0
    num_centroids = 0
    num_permissions = 0

    java_node_keys = {}
    java_node_name_tree = {}
    java_node_hash_tree = {}
    java_leaf_node_set = set()

    # Get software details
    software_details = get_software_details(main=main, input_path=input_path)
    try:
        redis = main.jrc.handle()
        input_id = get_input_id(input_path)

        # get the AllClassesSummary proto
        summary_proto = get_all_classes_summary(input_path=input_path, outdir=outdir, input_type=input_type, main=main)

        # maintain the classname to permission string mapping
        class_permissions = {class_pair.classname1: list(class_pair.classname2_permissions) for class_pair in
                             summary_proto.class_pairs if len(class_pair.classname2_permissions) > 0
                             } if main.USE_PERMISSION_STRINGS else {}

        used_non_application_class_set = set()
        for class_pair in summary_proto.class_pairs:
            if ((not class_pair.classname2_is_application_class)
                    and (class_pair.classname2.startswith(framework_prefix))):
                used_non_application_class_set.add(class_pair.classname2)

        for class_proto in summary_proto.classes:
            leaf_node_path = get_node_path(input_path=input_path, package_name=class_proto.package_name,
                                           class_name=class_proto.class_name)

            # Get all string constants in this class
            strings = {}
            str_count = 0

            # Get all classes in this class
            tmp_funcs = {}
            this_classes = {}
            this_class_count = 0

            # Get all function centroid in this class
            centroids = {}
            centroids_count = 0

            # Get this class
            tmp_normfuncs = {}
            normclasses = {}
            normclass_count = 0

            for method in class_proto.methods:

                # get string constants
                for string in method.string_constants:
                    if not string:
                        continue

                    if main.TEST_REPO:
                        logger.info("%s", string)
                        continue

                    # get identifier for this string
                    str_id = "strings-" + str(utils.get_key(main, string))

                    # accounting
                    strings.setdefault(str_id, 0)
                    strings[str_id] += 1
                    str_count += 1

                # get function signature
                func = get_no_package_func(method_proto=method, non_application_classes=used_non_application_class_set)
                if main.TEST_REPO:
                    logger.info("%s", func)

                tmp_funcs.setdefault(func, 0)
                tmp_funcs[func] += 1

                # get normalized identifier for this func
                norm_func = get_obfuscation_resilient_func(method_proto=method,
                                                           non_application_classes=used_non_application_class_set)
                if main.TEST_REPO:
                    logger.info("%s", norm_func)

                tmp_normfuncs.setdefault(norm_func, 0)
                tmp_normfuncs[norm_func] += 1

                # get centroid for this func
                if method.HasField('centroid'):
                    centroid_str = get_centroid_string(centroid=method.centroid,
                                                       centroidinvoke=method.centroid_with_invoke)
                    centroid_id = "centroids-" + str(utils.get_key(main, centroid_str))
                    if not main.TEST_REPO and centroid_id not in centroids and centroid_id not in java_node_keys:
                        # Map the centroid values to centroid keys, so that we can lookup!
                        # NOTE: this is not done in test_and_set, because this is a separate features set!
                        build_centroid_db(main=main, redis=redis, centroid=method.centroid,
                                          centroidinvoke=method.centroid_with_invoke,
                                          cdd_range=main.MAX_METHOD_DIFFERENCE_DEGREE)
                    # update centroid feature
                    centroids.setdefault(centroid_id, 0)
                    centroids[centroid_id] += 1
                    centroids_count += 1

            # get identifier for this class
            this_class = get_class_string(tmp_funcs, unique=False)
            if main.TEST_REPO:
                logger.info("%s", this_class)
            this_class_id = "classes-" + str(utils.get_key(main, this_class))
            this_classes.setdefault(this_class_id, 0)
            this_classes[this_class_id] += 1
            this_class_count += 1

            # get normalized identifier for this class
            norm_class = get_class_string(tmp_normfuncs, unique=False)
            if main.TEST_REPO:
                logger.info("%s", norm_class)
            norm_class_id = "normclasses-" + str(utils.get_key(main, norm_class))
            normclasses.setdefault(norm_class_id, 0)
            normclasses[norm_class_id] += 1
            normclass_count += 1

            # update the total counts
            num_strs += str_count
            num_classes += this_class_count
            num_normclasses += normclass_count
            num_centroids += centroids_count

            # TODO: Get all permissions in this class, this is only stored in class pairs
            # Get all permissions related to this class
            permissions = {}
            perm_count = 0
            if class_proto.class_name in class_permissions:
                for perm in class_permissions[class_proto.class_name]:

                    if main.TEST_REPO:
                        logger.info("%s", perm)

                    perm_id = "permissions-" + str(utils.get_key(main, perm))

                # accounting
                permissions.setdefault(perm_id, 0)
                permissions[perm_id] += 1
                perm_count += 1
            num_permissions += perm_count

            # skip this leaf node if it contains no features worth indexing
            num_indexing_features = this_class_count + str_count + normclass_count + centroids_count
            num_uniq_indexing_features = len(tmp_funcs) + len(strings) + len(normclasses) + len(centroids)
            num_indexing_features_dict = {'featcnt': num_indexing_features, 'uniqfeatcnt': num_uniq_indexing_features,
                                          'strcnt': str_count, 'uniqstrcnt': len(strings),
                                          'classcnt': this_class_count, 'uniqclasscnt': len(this_classes),
                                          'normclasscnt': normclass_count, 'uniqnormclasscnt': len(normclasses),
                                          'centroidcnt': centroids_count, 'uniqcentroidcnt': len(centroids)}
            if not num_indexing_features:
                logger.info("input %s no features found in %s", input_path, leaf_node_path)
                continue

            # log as requested
            if main.LOG_PER_FILE:
                logger.info("node: %s contains the following %d items: ", leaf_node_path, num_indexing_features)
                logger.info("%s strings: %s", str_count, strings)
                logger.info("%s classes: %s", this_class_count, this_classes)
                logger.info("%s normclasses: %s", normclass_count, normclasses)
                logger.info("%s centroid: %s", centroids_count, centroids)
                logger.info("%s permissions: %s", perm_count, permissions)
            else:
                logger.debug("node %s contains %d items: %d strings (%d), %d classes (%d),"
                             " %d centroids (%d), %d normclasses (%d), and %d permissions (%d)",
                             leaf_node_path, num_indexing_features, str_count, len(strings),
                             this_class_count, len(this_classes), centroids_count, len(centroids),
                             normclass_count, len(normclasses), perm_count, len(permissions))

            # get repo keys from this class
            num_java_indexing_keys += build_repo_indexing_features(input_path, java_node_keys, strings, this_classes,
                                                                   normclasses, centroids)

            # build hierarchical mappings
            if not main.TEST_REPO:

                # build a list of items present in this leaf node
                leaf_node_all_features = get_node_indexing_features(strings, this_classes, normclasses, centroids)
                if not leaf_node_all_features:
                    logger.warn("Failed to build item list for leaf node %s from repo %s. Ignoring!",
                                leaf_node_path, input_path)
                    continue

                # for normal hierarchical indexing, use simhash to generate the node id
                leaf_node_id = get_node_id(main=main, features=leaf_node_all_features, logger=logger)
                if not leaf_node_id:
                    logger.warn("Failed to get hash id for leaf node %s in repo %s. Ignoring!",
                                leaf_node_path, input_path)
                    continue

                # process leaf node items
                leaf_node_type = "files"
                count, leaf_node_id = index_node(main=main, redis=redis, repo_id=input_id, node_type=leaf_node_type,
                                                 node_id=leaf_node_id, node_path=leaf_node_path,
                                                 node_num_features_dict=num_indexing_features_dict,
                                                 node_features=leaf_node_all_features)

                # record unique features for different versions of a repo
                if main.USE_VERSION_DIFFERENCES:
                    try:
                        logger.debug("Building version table for %d features", len(leaf_node_all_features))
                        build_version_db(main=main, features=leaf_node_all_features,
                                         software_details=software_details, language="java", logger=logger)
                    except Exception as e:
                        exc_type, exc_obj, exc_tb = sys.exc_info()
                        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                        logger.error("[%s, %s, %s] Error building version database for %s: %s",
                                     exc_type, fname, exc_tb.tb_lineno, input_path, str(e))

                # finally build
                build_repo_node_tree(main=main, redis=redis, repo_id=input_id, repo_path=input_path,
                                     leaf_node_path=leaf_node_path, leaf_node_id=leaf_node_id,
                                     leaf_node_items=leaf_node_all_features,
                                     leaf_node_indexing_featcnt_dict=num_indexing_features_dict,
                                     repo_node_name_tree=java_node_name_tree, repo_node_hash_tree=java_node_hash_tree)
                java_leaf_node_set.add(leaf_node_path)

        if not num_java_indexing_keys:
            logger.info("Repo %s (md5hash: %s) contains no indexing keys!", input_path, input_id)
            return 0, 0, 0, 0

        if not main.TEST_REPO:
            # get unique repo identifier based on its contents
            logger.info("Building indexing table for %s features in %s (%s)",
                        num_java_indexing_keys, input_path, input_id)
            java_hash = index_repo_nodes(main=main, redis=redis, repo_id=input_id, repo_path=input_path,
                                         parent=input_path, repo_node_name_tree=java_node_name_tree,
                                         repo_node_hash_tree=java_node_hash_tree,
                                         repo_leaf_node_set=java_leaf_node_set)

        # compute the globally unique feature counters
        type2count = Counter(key.split('-')[0] for key in java_node_keys.keys())
        results = {'java_hash': java_hash, 'num_java_indexing_keys': num_java_indexing_keys,
                   'unique': len(java_node_keys), 'min_freq': min(java_node_keys.values()),
                   'max_freq': max(java_node_keys.values()),
                   'num_strs': num_strs, 'num_classes': num_classes, 'num_normclasses': num_normclasses,
                   'num_centroids': num_centroids, 'num_permissions': num_permissions,
                   'num_uniq_strs': type2count['strings'] if 'strings' in type2count else 0,
                   'num_uniq_classes': type2count['classes'] if 'classes' in type2count else 0,
                   'num_uniq_normclasses': type2count['normclasses'] if 'normclasses' in type2count else 0,
                   'num_uniq_centroids': type2count['centroids'] if 'centroids' in type2count else 0,
                   'num_uniq_permissions': type2count['permissions'] if 'permissions' in type2count else 0}

        # print logging information
        logger.info("Repo %s (md5hash: %s, simhash: %s) contains a total of %d keys"
                    " (unique %d, min freq %d, max freq %d) consisting of %d (%d) strings, %d (%d) classes,"
                    " %d (%d) normclasses, %d (%d) centroids, %d (%d) syscalls",
                    input_path, input_id, results['java_hash'], results['num_java_indexing_keys'],
                    results['unique'], results['min_freq'], results['max_freq'],
                    results['num_strs'], results['num_uniq_strs'], results['num_classes'], results['num_uniq_classes'],
                    results['num_normclasses'], results['num_uniq_normclasses'],
                    results['num_centroids'], results['num_uniq_centroids'],
                    results['num_permissions'], results['num_uniq_permissions'])

        if not main.TEST_REPO:
            # update the stats for input_id
            process_repo_results(redis=redis, repo_id=input_id, results=results)

            # record the input_path to input_id mapping, and the input_id to input_path mapping
            redis.hincrby(input_path, input_id, 1)
            redis.hset(input_id, "input_path", input_path)
            redis.hmset(input_id, software_details)
            logger.info("Finished indexing Repo %s (%s)", input_path, input_id)

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error("[%s, %s, %s] Error building version database for %s: %s",
                     exc_type, fname, exc_tb.tb_lineno, input_path, str(e))
        if main.failure_file:
            open(main.failure_file, 'a').write(input_path + '\n')

    finally:
        return num_java_indexing_keys, num_strs, num_classes, num_permissions


###########################################################
# Index java classes
###########################################################
def index_classes(main, input_path, input_type):
    """
    Index the input classes.

    :param main: the detector main module
    :param input_path: path to input
    :param input_type: type of input, can be ('class', 'jar', 'dex', 'apk')
    :return: True/False, successful or not
    """
    start = time.time()
    # global values
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger
    signature_java.logger = main.logger
    signature_java.stats_logger = main.stats_logger

    # extract signatures from input_path, insert into redis
    if main.keep_sig and main.java_sig_dir:
        if not os.path.exists(main.java_sig_dir):
            os.makedirs(main.java_sig_dir)
        outdir = main.java_sig_dir
    else:
        outdir = tempfile.mkdtemp(prefix="index_classes-")
    num_java_indexing_keys, num_strs, num_classes, num_permissions = build_db(main=main, input_path=input_path,
                                                                              input_type=input_type, outdir=outdir)
    # cleanup
    if not main.keep_sig:
        shutil.rmtree(outdir)
    # time logging
    end = time.time()
    if stats_logger:
        stats_dict = {'num_java_indexing_keys': num_java_indexing_keys, 'num_strs': num_strs,
                      'num_classes': num_classes, 'num_permissions': num_permissions, 'end': end, 'start': start,
                      'dbsize': main.jrc.handle().dbsize(), 'repo_count': main.jrc.handle().get('reposcnt')}
        stats_logger.info("time elapsed for indexing %s: %0.2f seconds, which has stats dict: %s",
                          input_path, end - start, stats_dict)
    return num_strs


###########################################################
# Indexer
###########################################################
def run_indexer(main, argv):
    global logger
    logger = main.logger
    signature_java.logger = main.logger

    # the outer args
    if len(argv) != 2:
        logger.error('expects two args')
        exit(1)
    if argv[0] == 'dump':
        main.TEST_REPO = True

    # the inner args
    argv = argv[1]
    if len(argv) < 1 or len(argv) > 2:
        logger.error('expects args: $input_path [$input_type]')
        exit(1)

    input_path = argv[0]
    input_type = argv[1] if len(argv) == 2 else 'jar'
    if not os.path.exists(input_path):
        logger.error('%s does not exist', input_path)
        exit(1)

    redis = main.jrc.handle()
    input_list = get_input_list(main=main, redis=redis, redis_pipe=main.jrc.pipeline(), input_path=input_path,
                                input_type=input_type, skip_scanned=True, skip_failure=True)

    print ("There are %d input to be indexed" % len(input_list))
    # start indexing
    # insert into database
    if input_list:
        # register signal handler
        signal = utils.Signal()
        signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

        # track progress
        count = len(input_list)

        # if requested parallelism
        if main.QUEUING and main.QUEUING == "Celery":
            from celery import group
            from celery_tasks import index_java_worker

            # group jobs
            count = 0
            input_count = len(input_list)
            for index in range(0, input_count, JOB_CHUNK):
                tmp_input_list = input_list[index: min(index + JOB_CHUNK, input_count)]
                if index + JOB_CHUNK > input_count:
                    logger.info("Processing the %d %d input" % (index / JOB_CHUNK + 1, input_count - index))
                else:
                    logger.info("Processing the %d %d input" % (index / JOB_CHUNK + 1, JOB_CHUNK))
                job = group(index_java_worker.s(item, input_type) for item in tmp_input_list)
                result = job.apply_async()
                try:
                    count += len(result.get())
                except Exception as e:
                    logger.error("Error signaturing jobs: %s", str(e))

        else:  # non-parallel instance
            pb = utils.Progressbar('Indexing %s(s): ' % input_type, count)
            pb.start()

            # scan loop
            count = 0
            for item in input_list:

                # check for interruption
                if signal.caught():
                    break

                if main.TEST_REPO:
                    pb.msg('Testing {0} '.format(item))
                else:
                    pb.msg('Indexing {0} '.format(item))

                # scan classes; already filtered
                num_strs = index_classes(main=main, input_path=item, input_type=input_type)

                # update progressbar
                count += 1
                pb.update(count)

            if not signal.caught():
                pb.finish()

        # log number of repos indexed
        total = redis.get("reposcnt")
        if total:
            if main.TEST_REPO:
                logger.critical("Indexed a total of %s artifacts (tested %d)", total, count)
            else:
                logger.critical("Indexed a total of %s artifacts (new: %d)", total, count)


#########################################################################
# Lookup similar nodes based on features, insert new node if none exist
#
# This test_and_set is designed to be thread safe. It tests whether *key* has been mapped to the specified *val* or
# similar *val* or not. If yes, return the matched value, o.w. map the key to the value.
# The logic is as follows:
#
# 1. get refcnt for key, if refcnt is too big, then we increase refcnt and consider the val as matched, go to Step 6.
# 2. if refcnt is fine, then we try to set (key, val) pair.
# 2.1 if someone has done this, then we consider val as matched, go to Step 6.
# 2.2 if someone is still working on this, wait until he finishes. if he succeeds, then consider val as matched
#       and go to Step 6, o.w. that guy failed and we restart from Step 1
# 2.3 if we are the first one to do this, go to Step 3
# 3. increase refcnt to indicate how many workers on working on current key, update score of val with -refcnt to
#       indicate when this worker joined the competition.
# 4. compare current val with all the existing values, to see whether val is similar to one of them. the compare order
#       is to first compare against the fixed values, then compare against the *first* joined temporary worker
#       (NOTE: c == 0 means in progress). If current worker, joined later than first worker, then wait longer,
#       vice versa. We need to reset the refcnt if we decide to wait (backoff), or we have found an similar val.
#       If we found similar value, go to Step 6, o.w. go to Step 5.
# 5. nothing similar was found, so we need to set the count (key, val), and then build the reverse mapping.
#       matched_val is val
# 6. return matched val
#########################################################################
def test_and_set(main, redis, repo_id, key_type, key, val_type, val, info_dict, simhash_thres=None,
                 restart=False, retries=5):
    uniq, total = info_dict['uniqfeatcnt'], info_dict['featcnt']
    count = int(uniq)
    simhash_thres = main.SIMHASH_DISTANCE if simhash_thres is None else simhash_thres

    # when a dir contains a single subdir
    if key_type == val_type and key == val:
        return key

    typed_key = get_typed_key(key_type, key)
    typed_val = get_typed_key(val_type, val)

    exception_retries = 5
    while exception_retries:
        try:
            matched_val = None

            # take reference count and check if this key has reached max popularity level
            refcnt = redis.hincrby(typed_key, 'refcnt', 0)
            if refcnt > main.MAX_PER_STR_MATCHING_REPO_COUNT:
                # matched val is ignored
                return val

            # check whether the (key, value) pair exists
            ret = redis.hsetnx(typed_key, typed_val, 0)
            logger.debug("key %s val: %s ret: %d", typed_key, typed_val, ret)
            if not ret:
                score = int(redis.hget(typed_key, typed_val))
                if score > 0:
                    # if (key, val) pair exists with a non-zero count
                    logger.debug("key id: %s same item id: %s", typed_key, typed_val)
                    return val
                else:
                    # if (key, val) pair exists with zero count, wait until he finishes
                    retries_counter = 0
                    while (redis.hexists(typed_key, typed_val) and int(
                            redis.hget(typed_key, typed_val)) <= 0 and retries_counter < retries):
                        logger.info("key id: %s same item id: %s, waiting", typed_key, typed_val)
                        time.sleep(random.randint(0, 4))
                        retries_counter += 1
                    if retries_counter >= retries:
                        # due to manual shutdown or other reasons, there maybe abnormal in-progress nodes, fix them!
                        redis.hset(typed_key, typed_val, count)
                    logger.info("handling same (key: %s, value: %s) pairs", typed_key, typed_val)
                    if redis.hexists(typed_key, typed_val):
                        # if (key, val) pair exists with a non-zero count
                        return val

                    # if (key, val) pair removes itself, we do the same thing again, this can be optimized by
                    # a redirect table
                    continue

            # if (key, value) pair doesn't exist, then check for similar ids
            refcnt = redis.hincrby(typed_key, 'refcnt', 1)
            redis.hincrby(typed_key, typed_val, -refcnt)
            backoff_count = 0

            # iterate over all matched items
            for v, c in sorted(redis.hgetall(typed_key).items(), key=operator.itemgetter(1), reverse=True):
                # skip reference, feature, and similarity counts
                if v in skip_set:
                    continue
                if v.startswith('repo-'):
                    continue

                c = int(c)

                # perform apples-apples comparison
                v_type, v_val = v.split('-')
                if v_type != val_type:
                    continue

                # the node comes after current node and is still under processing
                if c == 0:
                    logger.info(
                        "node comes after current node and is still under processing: %s, %s, current refcnt=%d", v, c,
                        refcnt)
                    continue

                # somebody else inserted temp node, compare distance
                elif c < 0 and long(v_val) != long(val):
                    # refcnt is the number of items when current node gets inserted
                    # -c is the number of items, when the other node gets inserted
                    # if the other node was inserted before current node, then we wait longer time
                    distance = get_simhash_distance(val, v_val)
                    if distance < 0:
                        logger.warn("failed to get simhash distance for (%s, %s) repo %s", \
                                    val, v_val, repo_id)
                    elif distance <= simhash_thres:
                        logger.info("restart distance(%d, %s) = %d", val, v_val, distance)
                        # the temp node still exists
                        cc = int(redis.hget(typed_key, v))
                        if cc <= 0:
                            # delete previously inserted temp node
                            redis.hdel(typed_key, typed_val)
                            redis.hincrby(typed_key, 'refcnt', -1)

                            # if it still exists in temp mode, then we wait longer time
                            backoff_count = max(refcnt + int(c), 0)
                            restart = True
                        else:
                            # this node was updgraded to permanent one
                            logger.info("upgraded key: %s similar files (%s, %s): %s cc: %s",
                                        typed_key, v_val, val, distance, cc)
                            matched_val = long(v_val)
                        break

                # we inserted temp node, skip ourselves
                elif int(c) == -refcnt and long(v_val) == long(val):
                    continue

                # exists a valid node, compare distance
                elif int(c) > 0 and long(v_val) != long(val):
                    distance = get_simhash_distance(val, v_val)
                    if distance < 0:
                        logger.warn("failed to get simhash distance for (%s, %s) repo %s",
                                    val, v_val, repo_id)
                    elif distance <= simhash_thres:
                        logger.debug("key: %d similar files (%s, %s): %s", key, v_val, val, distance)

                        # delete previously inserted temp node
                        redis.hdel(typed_key, typed_val)
                        redis.hincrby(typed_key, 'refcnt', -1)
                        matched_val = long(v_val)
                        break

                else:
                    raise Exception("Unhandled case! current node: repo-id -> %s, key-type -> %s, key -> %s,"
                                    " val -> %s, score -> %s, target val -> %s, target score -> %s",
                                    (repo_id, key_type, key, val, -refcnt, v_val, c))

            if restart:
                # backoff exponentially
                seconds = backoff_count  # random.randint(0, 3 + backoff_count)
                logger.info("Race condition! current node: repo-id -> %s, key-type -> %s, key -> %s,"
                            " val -> %s, score -> %s, target val -> %s, target score -> %s",
                            repo_id, key_type, key, val, -refcnt, v, c)
                logger.info("Sleeping %d seconds now!", seconds)
                time.sleep(seconds)

            # no match found
            elif not matched_val:
                logger.debug("inserting key %s val %s", typed_key, typed_val)

                # upgrade previously inserted temp node to a permanent one
                redis.hset(typed_key, typed_val, count)

                # track number of new key-value mappings, as indicator for number of this key type
                redis.incrby(key_type + 'cnt', 1)

                rtyped_val = get_rtyped_key(val_type, val)
                # record all values pointing to this key
                if val_type == 'files':
                    # for files, simply use total in the reverse mapping
                    redis.hsetnx(rtyped_val, typed_key, int(total))
                else:
                    # for directories, use the info dict in the reverse mapping
                    redis.hsetnx(rtyped_val, typed_key, info_dict)

                # track number of total features for a node
                if val_type == "files":
                    redis.hincrby(typed_val, get_feature_count_name(key_type), count)
                return val
            elif matched_val:
                return matched_val

        except rediscluster.exceptions.ClusterDownError as cde:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logger.error("[%s, %s, %s] Failed to lookup key %s for repo %s: %s",
                         exc_type, fname, exc_tb.tb_lineno, typed_key, repo_id, str(cde))
            time.sleep(5)
            exception_retries -= 1
            continue

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logger.error("[%s, %s, %s] Failed to lookup key %s for repo %s: %s",
                         exc_type, fname, exc_tb.tb_lineno, typed_key, repo_id, str(e))
            return None

        # should never come here
        return None


###########################################################################
# Build a single map of features from a list of individual maps of features
###########################################################################
def get_node_indexing_features(*item_map_list):
    items = {}
    try:
        for item_map in item_map_list:
            for feature, feature_freq in item_map.items():
                items[feature] = {'uniqfeatcnt': 1, 'featcnt': feature_freq}
    except Exception as e:
        logger.error("failed to build node item list: %s", str(e))
    finally:
        return items


###########################################################
# Maintain a map of all keys in a repo
###########################################################
def build_repo_indexing_features(repo_id, repo_keys, *item_maps):
    count = 0
    try:
        for item_map in item_maps:
            for k, v in item_map.items():
                if not k in repo_keys:
                    repo_keys[k] = 0
                repo_keys[k] += v
                count += v
        return count
    except Exception as e:
        logger.error("Failed to build node keys for repo %s: %s", repo_id, str(e))
        return 0


###########################################################
# Index node features
###########################################################
def index_node(main, redis, repo_id, node_type, node_id, node_path, node_num_features_dict, node_features):
    """
    :param main: the detector object
    :param redis: redis access
    :param repo_id: repo_id
    :param node_type: type of node to index
    :param node_id: id of node to index
    :param node_path: path of node to index
    :param node_num_features_dict: features dict {'featcnt': X, 'uniqfeatcnt': X, ...} for node
    :param node_features: child -> child_features_dict
    :return total number of child features indexed (pointing to node)
    """
    # feature_type can be one of: files, dirs, features, strings, classes
    count = 0
    node_similarity_map = {}
    similar_nid = None

    try:
        # XXX for non-leaf nodes, @feature_info contains (uniq_featcnt, total_featcnt)
        # for leaf nodes @feature_info contains (1, feature_freq)
        nid2features = {}
        # sort the features to reduce the race condition when two workers are indexing the same file, or item.
        # o.w. several workers can start from different position of workers and index different part of the repo.
        for feature, feature_info_dict in sorted(node_features.items(), key=lambda k: k[0]):
            uniq, total = feature_info_dict['uniqfeatcnt'], feature_info_dict['featcnt']
            logger.debug("feature %s info: uniq %d total %d count %d", feature, uniq, total, count)

            # get feature id and type
            feature_type, feature_id = feature.split('-')
            feature_id = long(feature_id)

            # lookup by ids of containing features to find similar nodes
            similar_nid = test_and_set(main=main, redis=redis, repo_id=repo_id, key_type=feature_type, key=feature_id,
                                       val_type=node_type, val=node_id, info_dict=feature_info_dict)

            # maintain a similarity map
            node_similarity_map.setdefault(similar_nid, 0)
            node_similarity_map[similar_nid] += total
            nid2features.setdefault(similar_nid, set())
            nid2features[similar_nid].add(feature)

            # track number of features processed
            count += total

        num_total_features = node_num_features_dict['featcnt']
        if count != num_total_features:
            logger.warn("processed only %d/%d features from node %s in repo %s",
                        count, num_total_features, node_path, repo_id)

        if count:
            # sort similar nodes based on the number of features matched
            node_similarity_pairs = sorted(node_similarity_map.items(), key=lambda k: k[1], reverse=True)
            logger.debug("node %s id: %d similar nodes: %s", node_path, node_id, node_similarity_pairs)

            # take the node with largest similarity count
            similar_nid = long(node_similarity_pairs[0][0])

            # for the features that maps to non-selected node, map them one more time!
            if len(nid2features) > 1:
                logger.info("patching %d orphaned features to parent node: %s",
                            node_num_features_dict['uniqfeatcnt'] - len(nid2features[similar_nid]), similar_nid)
                orphaned_count = 0
                nid2features.pop(similar_nid)
                for orphaned_feature in chain(*nid2features.values()):
                    orphaned_feature_info_dict = node_features[orphaned_feature]
                    orphaned_feature_type, orphaned_feature_id = orphaned_feature.split('-')
                    orphaned_feature_id = long(orphaned_feature_id)
                    mapped_id = test_and_set(main=main, redis=redis, repo_id=repo_id, key_type=orphaned_feature_type,
                                             key=orphaned_feature_id, val_type=node_type, val=similar_nid,
                                             info_dict=orphaned_feature_info_dict, simhash_thres=0)
                    orphaned_count += 1
                    if mapped_id != similar_nid:
                        logger.warn("mapped id not equal to similar id when simhash thres is 0, this is weird!")
                logger.info("patched %d orphaned features to parent node: %s", orphaned_count, similar_nid)

            # warning
            if similar_nid != node_id:
                logger.info(
                    "largest count node not same as current node for %s (total count: %d, node_id %s: count %d, similar_id %s: count %d)",
                    node_path, count, node_id, node_similarity_map.get(node_id, -1), similar_nid,
                    node_similarity_map.get(similar_nid))
        else:
            logger.warn("failed to get similar nodes for node %s repo %s", node_path, repo_id)

    except Exception as e:
        logger.error("failed to process items for node %s in repo %s: %s", node_path, repo_id, str(e))

    finally:
        return count, similar_nid


###########################################################
# Create parent child node mappings in a repo
###########################################################
def build_repo_node_tree(main, redis, repo_id, repo_path, leaf_node_path, leaf_node_id, leaf_node_items,
                         leaf_node_indexing_featcnt_dict, repo_node_name_tree, repo_node_hash_tree):
    try:
        path = leaf_node_path
        while path != repo_path:

            # get item and its parent
            child = os.path.basename(path)
            parent = os.path.dirname(path)

            # create name hash mapping
            if path == leaf_node_path and not path in repo_node_hash_tree:
                repo_node_hash_tree[path] = (leaf_node_id, leaf_node_items, leaf_node_indexing_featcnt_dict)
                logger.debug("%s -> %s", path, repo_node_hash_tree[path])

            # build parent-child list
            if parent not in repo_node_name_tree:
                repo_node_name_tree[parent] = []
            if child not in repo_node_name_tree[parent]:
                repo_node_name_tree[parent].append(child)

            # continue building parent-child list
            path = parent

    except Exception as e:
        logger.error("failed to build repo node tree at node %s for repo %s: %s", leaf_node_path, repo_id, str(e))


###########################################################
# Index all nodes in repo
###########################################################
def index_repo_nodes(main, redis, repo_id, repo_path, parent, repo_node_name_tree, repo_node_hash_tree,
                     repo_leaf_node_set=None):
    try:
        if not parent:
            logger.error("For repo %s invalid parent!", repo_id)
            return

        logger.debug("processing node %s", parent)
        if parent not in repo_node_name_tree:
            logger.error("For repo %s failed to get children for %s", repo_id, parent)
            return

        children = repo_node_name_tree[parent]
        logger.debug("%s -> %s", parent, children)

        leaf_nodes = {}
        children_ids = {}
        parent_num_indexing_features_dict = {}

        for child in children:

            # child absolute path
            child_path = parent + "/" + child
            # In java, files -> classes, dirs -> packages
            if repo_leaf_node_set and child_path in repo_leaf_node_set:
                child_typ = "files"
            else:
                child_typ = "dirs"

            # make sure child hash id exists
            if child_path not in repo_node_hash_tree:
                logger.debug("requesting processing for %s", child_path)
                index_repo_nodes(main, redis, repo_id, repo_path, child_path, repo_node_name_tree, repo_node_hash_tree,
                                 repo_leaf_node_set)
                if child_path not in repo_node_hash_tree:
                    logger.error("For repo %s failed to get ID for child %s", repo_id, child_path)
                    continue

            # get child hash id
            child_id, leaf_hashes, child_num_indexing_features_dict = repo_node_hash_tree[child_path]
            child = get_typed_key(typ=child_typ, key=child_id)

            # maintain a map of all children, their types with freq count
            if child not in children_ids:
                children_ids[child] = child_num_indexing_features_dict

                # track num of indexing features across all siblings
                for num_type in child_num_indexing_features_dict:
                    parent_num_indexing_features_dict.setdefault(num_type, 0)
                    parent_num_indexing_features_dict[num_type] += child_num_indexing_features_dict[num_type]

                # concatenate features across all siblings
                leaf_nodes.update(leaf_hashes)

            logger.info("Hash(%s) -> %s [tokens: %d child indexing features count %s]",
                        child_path, child, len(leaf_hashes), child_num_indexing_features_dict)

        # all children are available now
        num_children = len(children_ids)
        logger.debug("leaf nodes for parent %s is %s", parent, leaf_nodes)

        parent_total_index_featcnt = parent_num_indexing_features_dict['featcnt']
        parent_uniq_index_featcnt = parent_num_indexing_features_dict['uniqfeatcnt']

        # all children are available now, derive parent hash id
        parent_id = get_node_id(main=main, features=leaf_nodes, logger=logger)
        if not parent_id:
            logger.error("For repo %s failed to get ID for parent %s", repo_id, parent)
            return

        # check if a node similar to parent exists
        node_type = "dirs"
        count, parent_id = index_node(main=main, redis=redis, repo_id=repo_id, node_type=node_type, node_id=parent_id,
                                      node_path=parent, node_num_features_dict=parent_num_indexing_features_dict,
                                      node_features=children_ids)
        if count != parent_total_index_featcnt:
            logger.warn("processed only %d/%d leaf nodes for parent: %s repo: %s",
                        count, parent_total_index_featcnt, parent, repo_id)

        # insert into database if not exists
        repo_node_hash_tree[parent] = (parent_id, leaf_nodes, parent_num_indexing_features_dict)

        if parent == repo_path:
            logger.info("Hash(%s) -> (simhash: %d, md5hash: %s) [%d]", parent, parent_id, repo_id, len(leaf_nodes))
            typed_top_key = get_typed_key(node_type, parent_id)
            # record mapping between top-directories simhash and repo-id
            redis.hincrby(typed_top_key, repo_id, int(parent_uniq_index_featcnt))
            redis.hsetnx(repo_id, typed_top_key, parent_num_indexing_features_dict)
            logger.info("Repo(%s) -> (%s, %s)", typed_top_key, repo_path, repo_id)

        return parent_id

    except Exception as e:
        logger.error("failed to process repo dir %s: %s", parent, str(e))
        return None


###########################################################
# Process results from a repo
###########################################################
def process_repo_results(redis, repo_id, results):
    # set number of keys and max/min frequency of appearance in this repo
    try:
        # add num of unique strings
        redis.hmset(repo_id, {'total': results['num_java_indexing_keys'], 'unique': results['unique'],
                              'min_score': results['min_freq'], 'max_score': results['max_freq']})
        # total number of repos
        redis.incrby("reposcnt", 1)

        # log everything
        if stats_logger:
            ratio = float(results['unique']) / results['num_java_indexing_keys']
            stats_logger.info("%s, %d, %d, %0.2f, %d, %d", repo_id, results['num_java_indexing_keys'],
                              results['unique'],
                              ratio, results['min_freq'], results['max_freq'])
    except Exception as e:
        logger.error("Error processing results for repo %s: %s", repo_id, str(e))
