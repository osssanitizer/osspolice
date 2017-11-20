import operator
import os
import random
import shutil
import sys
import time
import rediscluster
from ast import literal_eval
from itertools import chain
from os.path import splitext, basename

import signature
import utils
from common import skip_set, get_typed_key, Ext2FileType
from signature import get_all_files_summary, fetch_and_filter_repo_list
from utils import get_simhash_distance, get_node_id
from version_db import build_version_db, VERSION_DB_TIMEOUT, VERSION_DB_RETRIES

# encoding=utf8
reload(sys)
sys.setdefaultencoding('utf8')

###########################################################
# init state
###########################################################
profiler = None
logger = None
stats_logger = None
dump_logger = None
JOB_CHUNK = 50000


###########################################################
# Helper functions
###########################################################
def update_redis_license(redis, node_path, node_id, node_licenses):
    existing_licenses = redis.hget(node_id, "license")
    if existing_licenses:
        existing_licenses = literal_eval(existing_licenses)
        new_licenses = set(node_licenses) - set(existing_licenses)
        if len(new_licenses) == 0:
            logger.info("license %s for node %s (id %s) has already been set!", node_licenses, node_path, node_id)
        else:
            logger.info("adding new license %s for node %s (id %s)", new_licenses, node_path, node_id)
            all_licenses = list(set(node_licenses) | set(existing_licenses))
            redis.hset(node_id, "license", all_licenses)
    else:
        logger.info("setting licenses %s for node %s (id %s)", node_licenses, node_path, node_id)
        redis.hset(node_id, "license", node_licenses)


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

    typed_key = get_typed_key(typ=key_type, key=key)
    typed_val = get_typed_key(typ=val_type, key=val)

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
                # get exiting score for this (key, value) pair
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
                        # (key, val) pair exists with a non-zero count
                        return val

                    # if (key, val) pair removes itself, we do the same thing again, this
                    # can be optimized by a redirect table
                    continue

            # if (key, value) pair doesn't exist, then check for similar ids
            refcnt = redis.hincrby(typed_key, 'refcnt', 1)
            redis.hincrby(typed_key, typed_val, -refcnt)
            backoff_count = 0

            # iterate over all matched items
            for v, i in sorted(redis.hgetall(typed_key).items(), key=operator.itemgetter(1), reverse=True):
                # skip reference, feature, and similarity counts, branch and repo
                if v in skip_set:
                    continue
                if v.startswith(("branch-", "repo-",)):
                    continue

                # u,t = i.split(',')
                c = int(i)
                logger.debug("key %s val: %s v: %s c: %s", typed_key, typed_val, v, c)

                # perform apples-apples comparison
                v_type, v_val = v.split('-')
                if v_type != val_type:
                    continue

                # node added while we entered the loop, continue
                if int(c) == 0:
                    logger.info("node comes after current node and is still under processing: "
                                "%s, %s, current refcnt=%d", v, c, refcnt)
                    continue

                # somebody else inserted temp node before we polled
                if int(c) < 0 and long(v_val) != long(val):
                    # refcnt is the number of items when current node gets inserted
                    # -c is the number of items, when the other node gets inserted
                    # we are here because the other node was inserted before our node
                    # compare distance
                    distance = get_simhash_distance(val, v_val)
                    if distance < 0:
                        logger.warn("failed to get simhash distance for (%s, %s) repo %s",
                                    val, v_val, repo_id)
                    elif distance <= simhash_thres:
                        logger.info("restart distance(%d, %s) = %d", val, v_val, distance)
                        # the temp node still exits
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

                # we inserted a temp node, skip ourselves
                elif int(c) == -refcnt and long(v_val) == long(val):
                    continue

                # exists a valid node, compare distance
                elif int(c) > 0 and long(v_val) != long(val):
                    distance = get_simhash_distance(val, v_val)
                    if distance < 0:
                        logger.warn("failed to get simhash distance for (%s, %s) repo %s",
                                    val, v_val, repo_id)
                    elif distance <= simhash_thres:
                        logger.debug("key: %s similar files (%s, %s): %s", typed_key, v_val, val, distance)

                        # delete previously inserted temp node
                        redis.hdel(typed_key, typed_val)
                        redis.hincrby(typed_key, 'refcnt', -1)
                        matched_val = long(v_val)
                        break
                        # create new mapping with -tive count to indicate a similarity mapping
                        # if redis.hsetnx(typed_key, v, -count):
                        #    # track number of features from similar nodes
                        #    redis.hincrby(v, 'simcnt', count)
                else:
                    raise Exception("Unhandled case! repo-id %s key %s val %s count %s v %s c %s",
                                    (repo_id, typed_key, typed_val, count, v, c))

            if restart:
                # backoff exponentially
                seconds = backoff_count  # random.randint(0, 3 + backoff_count)
                logger.info("Race condition! repo-id %s key %s val %s refcnt %s",
                            repo_id, typed_key, typed_val, refcnt)
                logger.info("Sleeping %d seconds now!", seconds)
                time.sleep(seconds)

            # no match found
            elif not matched_val:
                logger.debug("inserting key %s val %s", typed_key, typed_val)

                # upgrade previously inserted temp node to a permanent one
                redis.hset(typed_key, typed_val, count)

                # track number of new key-value mappings, as indicator for number of this key type
                redis.incrby(key_type + 's', 1)

                # record all values pointing to this key
                if val_type == 'file':
                    # for files, simply use total in the reverse mapping
                    redis.hsetnx(val_type + '_' + str(val), key_type + '_' + str(key), int(total))
                else:
                    # for directories, use the info dict in the reverse mapping
                    redis.hsetnx(val_type + '_' + str(val), key_type + '_' + str(key), info_dict)

                # track number of total features for a node
                if val_type == 'file':
                    redis.hincrby(typed_val, key_type + 'cnt', count)
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
# Process results from a repo
###########################################################
def process_repo_results(redis, repo_id, results):
    # set number of keys and max/min frequency of appearance in this repo
    try:
        # total cstrs (one with largest score)
        total_num_keys = results[1]
        # uniq cstrs (count all)
        num_uniq_keys = results[2]
        # cstr with min freq (one with lowest score)
        min_score = results[3]
        # cstr with max freq (one with second largest score)
        max_score = results[4]
        # add num of unique strings
        redis.hmset(get_typed_key(typ='repo', key=repo_id),
                    {'total': total_num_keys, 'unique': num_uniq_keys, 'max_score': max_score, 'min_score': min_score})

        # total number of repos
        redis.incrby("repos", 1)

        # log everything
        if stats_logger:
            ratio = float(num_uniq_keys) / total_num_keys
            stats_logger.info("%s, %d, %d, %0.2f, %d, %d", repo_id, total_num_keys, num_uniq_keys, ratio,
                              min_score, max_score)
    except Exception as e:
        logger.error("Error processing results for repo %s: %s", repo_id, str(e))


###########################################################
# Index node features
###########################################################
def index_node(main, redis, repo_id, branch, node_type, node_id, node_path, node_num_indexing_features_dict,
               node_features):
    """
    :param main: the detector object
    :param redis: redis access
    :param repo_id: repo_id
    :param branch: branch id
    :param node_type: type of node to index
    :param node_id: id of node to index
    :param node_path: path of node to index
    :param node_num_indexing_features_dict: features dict {'featcnt': X, 'uniqfeatcnt': X, ...} for node
    :param node_features: child -> child_features_dict
    :return total number of child features indexed (pointing to node)
    """
    count = 0
    node_similarity_map = {}
    similar_nid = None

    try:
        # XXX for non-leaf nodes, @feature_info contains (uniq_featcnt, total_featcnt)
        # for leaf nodes @feature_info contains (1, feature_freq)
        nid2features = {}
        for feature, feature_info_dict in node_features.items():
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

        # validate processed count
        num_total_features = node_num_indexing_features_dict['featcnt']
        if count != num_total_features:
            logger.warn("processed only %d/%d features from node %s in repo %s",
                        count, num_total_features, node_path, repo_id)

        if count:
            # sort similar nodes based on the number of features matched
            node_similarity_pairs = sorted(node_similarity_map.items(), key=lambda x: x[1], reverse=True)
            logger.info("node %s id: %d similar nodes: %s", node_path, node_id, node_similarity_map)

            # take the node with largest similarity count
            similar_nid = long(node_similarity_pairs[0][0])

            # for the features that maps to non-selected node, map them one more time!
            if len(nid2features) > 1:
                logger.info("patching %d orphaned features to parent node: %s",
                            node_num_indexing_features_dict['uniqfeatcnt'] - len(nid2features[similar_nid]),
                            similar_nid)
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
                logger.info("largest count node not same as current node for %s", node_path)
        else:
            logger.warn("failed to get similar nodes for node %s repo %s branch %s", node_path, repo_id, branch)

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error("[%s, %s, %s] failed to process items for node %s in repo %s branch %s: %s",
                     exc_type, fname, exc_tb.tb_lineno, node_path, repo_id, branch, str(e))

    finally:
        return count, similar_nid


###########################################################
# Use regex to extract syscalls/all functions (names)/strings/variables
###########################################################
def build_db_features(main, repo_id, file_path, feature_list, feature_type):
    if feature_type == 'string_literal':
        prefix = 'str-'
    elif feature_type == 'variable':
        prefix = 'var-'
    elif feature_type == 'exported_function':
        prefix = 'func-'
    elif feature_type == 'exported_function_name':
        prefix = 'funcname-'
    elif feature_type == 'system_call':
        prefix = 'syscall-'
    else:
        raise Exception("Unknown feature_type: " + feature_type)

    features = {}
    count = 0
    for feat in feature_list:
        try:
            # filter out short strings
            if (feature_type == 'string_literal' and
                    (not feat or len(feat) < main.MIN_STRING_LEN or not utils.is_ascii(feat))):
                continue

            # if requested to dump all features
            if main.TEST_REPO:
                features.setdefault(prefix + feat, 0)
                features[prefix + feat] += 1
                count += 1
                continue

            # get identifier for this feature
            feat_id = prefix + str(utils.get_key(main, feat))
            if not feat_id:
                logger.error('repo %s file: %s failed to get feat id for %s %s',
                             repo_id, file_path, feature_type, feat_id)
                continue

            # accounting
            features.setdefault(feat_id, 0)
            features[feat_id] += 1
            count += 1

        except Exception as e:
            logger.error("regex failed to build feature %s %s for repo %s: %s", feature_type, feat, repo_id, str(e))

    return count, features


###########################################################
# Index all nodes in repo
###########################################################
def index_repo_nodes(main, redis, repo_id, branch, repo_path, parent, repo_node_name_tree, repo_node_hash_tree):
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

        for child_name in children:

            # child absolute path
            child_path = parent + "/" + child_name

            # make sure child hash id exists
            if child_path not in repo_node_hash_tree:
                logger.debug("requesting processing for %s", child_path)
                index_repo_nodes(main, redis, repo_id, branch, repo_path, child_path,
                                 repo_node_name_tree, repo_node_hash_tree)
                if child_path not in repo_node_hash_tree:
                    logger.error("For repo %s failed to get ID for child %s",
                                 repo_id, child_path)
                    continue

            child_id, leaf_hashes, child_num_indexing_features_dict, child_type = repo_node_hash_tree[child_path]
            child = get_typed_key(typ=child_type, key=child_id)

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

        parent_total_index_featcnt = parent_num_indexing_features_dict['featcnt']
        parent_uniq_index_featcnt = parent_num_indexing_features_dict['uniqfeatcnt']

        # all children are available now, derive parent hash id
        parent_id = get_node_id(main=main, features=leaf_nodes, logger=logger)
        if not parent_id:
            logger.error("For repo %s failed to get ID for parent %s", repo_id, parent)
            return

        logger.debug("%s -> child count %d: %s", parent, num_children, children_ids)

        # check if a node similar to parent exists
        parent_type = "dir"
        count, parent_id = index_node(main=main, redis=redis, repo_id=repo_id, branch=branch, node_type=parent_type,
                                      node_id=parent_id, node_path=parent,
                                      node_num_indexing_features_dict=parent_num_indexing_features_dict,
                                      node_features=children_ids)
        if count != parent_total_index_featcnt:
            logger.warn("processed only %d/%d leaf nodes for parent: %s repo: %s",
                        count, parent_total_index_featcnt, parent, repo_id)

        # insert into database if not exists
        repo_node_hash_tree[parent] = (parent_id, leaf_nodes, parent_num_indexing_features_dict, parent_type)

        if parent == repo_path:
            logger.info("Hash(%s) -> %s %s", parent, parent_id, parent_num_indexing_features_dict)
            # branch itself is not unique enough, so we should add repo id to the key to increase entropy!
            branch_id = get_typed_key(typ=repo_id, key=branch)
            redis.hincrby('dir-' + str(parent_id), 'branch-' + branch_id, int(parent_uniq_index_featcnt))
            redis.hincrby('branch-' + branch_id, 'repo-' + repo_id, int(parent_uniq_index_featcnt))
            redis.hsetnx("branch_" + branch_id, 'dir_' + str(parent_id), parent_num_indexing_features_dict)
            redis.hsetnx("repo_" + repo_id, 'branch_' + branch_id, parent_num_indexing_features_dict)
            logger.info("Repo(%d) -> (%s, %s)", parent_id, branch_id, repo_id)

        return parent_id

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error("[%s, %s, %s] failed to process repo dir %s: %s",
                     exc_type, fname, exc_tb.tb_lineno, parent, str(e))
        return None


###########################################################
# Create parent child node mappings in a repo
###########################################################
def build_repo_node_tree(main, redis, repo_id, repo_path, leaf_node_path, leaf_node_id, leaf_node_indexing_features,
                         leaf_node_indexing_featcnt_dict, repo_node_name_tree, repo_node_hash_tree):
    try:
        path = leaf_node_path
        while path != repo_path:

            # get child and its parent
            child = os.path.basename(path)
            parent = os.path.dirname(path)

            # create name hash mapping
            if path == leaf_node_path and path not in repo_node_hash_tree:
                leaf_node_type = 'file'
                repo_node_hash_tree[path] = (leaf_node_id, leaf_node_indexing_features, leaf_node_indexing_featcnt_dict,
                                             leaf_node_type)
                logger.debug("%s -> %s", path, repo_node_hash_tree[path])

            # build parent-child list
            repo_node_name_tree.setdefault(parent, set())
            repo_node_name_tree[parent].add(child)

            # continue building parent-child list
            path = parent

    except Exception as e:
        logger.error("failed to build repo node tree at node %s for repo %s: %s", leaf_node_path, repo_id, str(e))


###########################################################
# Maintain a map of all features in a repo
###########################################################
def build_repo_indexing_features(repo_id, repo_keys, *item_maps):
    count = 0
    try:
        for item_map in item_maps:
            for k, v in item_map.items():
                if k not in repo_keys:
                    repo_keys[k] = v
                else:
                    repo_keys[k] += v
                count += 1
        return count
    except Exception as e:
        logger.error("Failed to build node keys for repo %s: %s", repo_id, str(e))
        return 0


###########################################################
# Build database
###########################################################
def build_db(main, branch_details, dir2license, file2features):
    """
    Builds database of strings, functions, and syscalls in a repo
    returns count
    """
    redis = main.nrc.handle()
    branch = branch_details['branch']
    repo_id = branch_details['repo_id']
    repo_path = branch_details['branch_path']
    repo_hash = num_strs = num_vars = num_funcnames = num_funcs = num_syscalls = 0
    num_repo_indexing_features = 0
    repo_node_name_tree = {}
    repo_node_hash_tree = {}
    if main.TEST_REPO:
        dump = {}
    leaf_node_path = None

    # get strings
    build_db_start = time.time()
    try:
        repo_indexing_features = {}
        for file_path, features in file2features.items():

            # node path
            leaf_node_path = file_path
            logger.info("Working with leaf node %s", leaf_node_path)
            strings = features['string_literal']
            variables = features['variable']
            functionnames = features['exported_function_name']
            functions = features['exported_function']
            syscalls = features['system_call']

            str_count = funcname_count = func_count = var_count = syscall_count = 0
            uniqstr_count = uniqfuncname_count = uniqfunc_count = uniqvar_count = uniqsyscall_count = 0
            try:
                # build all strings in this file
                str_count, strings = build_db_features(main, repo_id, file_path, strings, 'string_literal')
                uniqstr_count = len(strings)
                num_strs += str_count
            except Exception as e:
                raise Exception("failed to build strings: " + str(e))
            try:
                # build all global variables in this file
                var_count, variables = build_db_features(main, repo_id, file_path, variables, 'variable')
                uniqvar_count = len(variables)
                num_vars += var_count
            except Exception as e:
                raise Exception("failed to build variables: " + str(e))
            try:
                # get all function names in this file
                funcname_count, functionnames = build_db_features(main, repo_id, file_path, functionnames,
                                                                  'exported_function_name')
                uniqfuncname_count = len(functionnames)
                num_funcnames += funcname_count
            except Exception as e:
                raise Exception("failed to build functionnames: " + str(e))
            try:
                # get all functions in this file
                func_count, functions = build_db_features(main, repo_id, file_path, functions, 'exported_function')
                uniqfunc_count = len(functions)
                num_funcs += func_count
            except Exception as e:
                raise Exception("failed to build functions: " + str(e))
            try:
                # get all system calls in this file
                syscall_count, syscalls = build_db_features(main, repo_id, file_path, syscalls, 'system_call')
                uniqsyscall_count = len(syscalls)
                num_syscalls += syscall_count
            except Exception as e:
                raise Exception("failed to build syscalls: " + str(e))

            # skip this leaf node if it contains no features worth indexing
            num_total_indexing_features = funcname_count + func_count + str_count + var_count + syscall_count
            num_uniq_indexing_features = len(functionnames) + len(functions) + len(strings) + len(variables) + len(
                syscalls)
            num_indexing_features_dict = {'featcnt': num_total_indexing_features,
                                          'uniqfeatcnt': num_uniq_indexing_features,
                                          'strcnt': str_count, 'uniqstrcnt': uniqstr_count,
                                          'varcnt': var_count, 'uniqvarcnt': uniqvar_count,
                                          'funccnt': func_count, 'uniqfunccnt': uniqfunc_count,
                                          'funcnamecnt': funcname_count, 'uniqfuncnamecnt': uniqfuncname_count,
                                          'syscallcnt': syscall_count, 'uniqsyscallcnt': uniqsyscall_count}
            if not num_total_indexing_features:
                logger.info("repo id %s no features found in %s", repo_id, leaf_node_path)
                continue

            # log as requested
            if main.LOG_PER_FILE:
                logger.info("node: %s contains the following uniq %d total %d indexing features: ",
                            leaf_node_path, num_uniq_indexing_features, num_total_indexing_features)
                logger.info("%d strings: %s", str_count, strings)
                logger.info("%d variables: %s", var_count, variables)
                logger.info("%d functionnames: %s", funcname_count, functionnames)
                logger.info("%d functions: %s", func_count, functions)
                logger.info("%d system calls: %s", syscall_count, syscalls)
            else:
                logger.info("node %s contains uniq %d total %d items: "
                            "%d strings, %d variables, %d functionnames, %d functions, and %d system calls",
                            leaf_node_path, num_uniq_indexing_features, num_total_indexing_features,
                            str_count, var_count, funcname_count, func_count, syscall_count)

            # get repo keys from this file
            num_repo_indexing_features += build_repo_indexing_features(repo_id, repo_indexing_features, strings,
                                                                       variables, functionnames, functions)

            # dump if requested
            if main.TEST_REPO:
                dump.update(strings)
                dump.update(variables)
                dump.update(functionnames)
                dump.update(functions)
                dump.update(syscalls)

            else:
                # build a list of items present in this leaf node
                leaf_node_indexing_features = get_node_indexing_features(strings, variables, functionnames, functions)
                if not leaf_node_indexing_features:
                    logger.warn("Failed to build indexing feature list for leaf node %s from repo %s. Ignoring!",
                                leaf_node_path, repo_id)
                    continue

                # get unique node identifier based on the features it contains
                leaf_node_id = get_node_id(main=main, features=leaf_node_indexing_features, logger=logger)
                if not leaf_node_id:
                    logger.warn("Failed to get hash id for leaf node %s in repo %s. Ignoring!",
                                leaf_node_path, repo_id)
                    continue

                # index leaf node
                leaf_node_type = "file"
                count, leaf_node_id = index_node(
                    main=main, redis=redis, repo_id=repo_id, branch=branch, node_type=leaf_node_type,
                    node_id=leaf_node_id, node_path=leaf_node_path,
                    node_num_indexing_features_dict=num_indexing_features_dict,
                    node_features=leaf_node_indexing_features)

                typed_leaf_id = get_typed_key(typ=leaf_node_type, key=leaf_node_id)
                # get the license for the current c/c++ file
                if main.SCAN_FILES_FOR_LICENSE and 'license' in features and features['license']:
                    update_redis_license(redis=redis, node_path=file_path, node_id=typed_leaf_id,
                                         node_licenses=features['license'])
                    logger.info("detected license %s in file %s (id %s)", features['license'], file_path, typed_leaf_id)

                # set leaf node type, h/c/hpp/cpp
                _, leaf_ext = splitext(leaf_node_path)
                if leaf_ext in Ext2FileType:
                    redis.hsetnx(typed_leaf_id, "filetype", Ext2FileType[leaf_ext])
                # set leaf node path
                leaf_name = basename(leaf_node_path)
                redis.hsetnx(typed_leaf_id, "filename", leaf_name)

                # record unique features for different versions of a repo
                if main.USE_VERSION_DIFFERENCES:
                    attempts = VERSION_DB_RETRIES
                    while attempts:
                        try:
                            # register timeout handler
                            with utils.time_limit(VERSION_DB_TIMEOUT):
                                version_start = time.time()
                                logger.info("Building version table for %d features", len(leaf_node_indexing_features))
                                build_version_db(main=main, features=leaf_node_indexing_features,
                                                 software_details=branch_details, language="native", logger=logger)
                                logger.info("Building version table for %d features, took %s seconds",
                                            len(leaf_node_indexing_features), time.time() - version_start)
                                break

                        # timed out
                        except utils.TimeoutException as te:
                            logger.error("Version db for %s %s", file_path, str(te))
                            attempts -= 1
                            continue
                    if attempts <= 0:
                        logger.info("Error building version database for %s: %s", repo_path, file_path)

                # finally build
                build_repo_node_tree(main=main, redis=redis, repo_id=repo_id, repo_path=repo_path,
                                     leaf_node_path=leaf_node_path, leaf_node_id=leaf_node_id,
                                     leaf_node_indexing_features=leaf_node_indexing_features,
                                     leaf_node_indexing_featcnt_dict=num_indexing_features_dict,
                                     repo_node_name_tree=repo_node_name_tree,
                                     repo_node_hash_tree=repo_node_hash_tree)

        if main.TEST_REPO:
            try:
                import csv
                path = dump_logger.handlers[1].baseFilename
                if main.STATS:
                    fieldnames = ['strs', 'vars', 'funcnames', 'funcs', 'total']
                    writer = csv.DictWriter(open(path, 'w'), fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerow({'strs': num_strs, 'vars': num_vars, 'funcnames': num_funcnames, 'funcs': num_funcs,
                                     'total': num_strs + num_vars + num_funcnames + num_funcs})
                else:
                    fieldnames = ['type', 'freq', 'feature']
                    writer = csv.DictWriter(open(path, 'w'), fieldnames=fieldnames)
                    writer.writeheader()
                    for k, v in sorted(dump.items(), key=lambda x: x[1], reverse=True):
                        t, k = k.split('-', 1)
                        writer.writerow({'type': t, 'freq': v, 'feature': k})
                return True
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                logger.error("[%s, %s, %s] Error dumping features for repo %s: %s", \
                             exc_type, fname, exc_tb.tb_lineno, repo_id, str(e))
                return None

        # Not TEST_REPO
        if not num_repo_indexing_features:
            return True

        # get unique repo identifier based on its contents
        repo_hash = index_repo_nodes(main, redis, repo_id, branch, repo_path, repo_path,
                                     repo_node_name_tree, repo_node_hash_tree)
        # Add the detected license to indexing table
        if len(dir2license):
            for dir_path, dir_lic in dir2license.items():
                # Because all the non repo-path has been excluded, so only root will be included!
                if dir_path in repo_node_hash_tree:
                    typed_dir_id = get_typed_key(typ="dir", key=repo_node_hash_tree[dir_path][0])
                    update_redis_license(redis=redis, node_path=dir_path, node_id=typed_dir_id, node_licenses=dir_lic)
                    logger.info("detected license %s in dir %s (id %s)", dir_lic, dir_path, typed_dir_id)
                else:
                    logger.info("detected license %s in dir %s, but it doesn't have node id!", dir_lic, dir_path)
            if repo_path in dir2license:
                branch_id = get_typed_key(typ=repo_id, key=branch)
                typed_branch_id = get_typed_key(typ="branch", key=branch_id)
                branch_lic = dir2license[repo_path]
                update_redis_license(redis=redis, node_path=repo_path, node_id=typed_branch_id,
                                     node_licenses=branch_lic)
                logger.info("detected license %s in branch %s (id %s)", branch_lic, repo_path, typed_branch_id)

        results = [repo_hash, num_repo_indexing_features, len(repo_indexing_features),
                   min(repo_indexing_features.values()), max(repo_indexing_features.values()),
                   num_strs, num_vars, num_funcnames, num_funcs, num_syscalls]

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error("[%s, %s, %s] Error building database for repo %s branch %s node %s: %s",
                     exc_type, fname, exc_tb.tb_lineno, repo_id, branch, leaf_node_path, str(e))
        return None

    # update the redis database
    logger.info("build_db for repo %s, branch %s, repo path %s, took time %s",
                repo_id, branch, repo_path, time.time() - build_db_start)
    if not main.TEST_REPO and type(results) == list:
        logger.info("Repo %s (%s) contains a total of %d keys (unique %d, min freq %d, "
                    "max freq %d) consisting of %d strings, %d variables, %d functionnames, %d functions, %d syscalls",
                    repo_id, results[0], results[1], results[2], results[3], results[4],
                    results[5], results[6], results[7], results[8], results[9])
        process_repo_results(redis, repo_id, results)
    return results


def index_repo(main, root_repo_path, item, branch=None):
    global logger, profiler, dump_logger, stats_logger
    logger = main.logger
    profiler = main.profiler
    stats_logger = main.stats_logger
    signature.logger = main.logger
    signature.stats_logger = main.stats_logger

    # index branches
    count = 0
    for branch_details, dir2license, file2features in get_all_files_summary(
            main=main, root_repo_path=root_repo_path, item=item, branch=branch):
        # all the features are available now!
        repo_name = branch_details['repo_name']
        repo_id = branch_details['repo_id']
        branch = branch_details['branch']
        branch_path = branch_details['branch_path']

        if main.TEST_REPO:
            try:
                import logger as applogger
                logfilepath = '/tmp'
                if main.MODE == 'Celery':
                    if not main.STATS:
                        logfilepath += '/index'
                    else:
                        logfilepath += '/index_worker'
                else:
                    logfilepath += '/index'
                if main.STATS:
                    logfilepath += '_stats_' + str(os.getpid()) + '_' + \
                                   utils.ts_now_str(fmt='%Y_%m_%d_%H_%M_%S') + '.csv'
                    if main.MODE == 'Celery':
                        dump_logger = applogger.Logger("Dump", logfilepath).get()
                    else:
                        dump_logger = applogger.Logger("Dump" + branch, logfilepath).get()
                else:
                    logfilepath += '_dump_' + repo_name.replace('/', '_') + '_' + branch + '.csv'
                    dump_logger = applogger.Logger("Dump" + branch, logfilepath).get()
            except Exception as be:
                logger.error("clone repo %s, name %s failed! Error: %s", repo_id, repo_name, str(be))
                continue

        # log steps taken
        if not main.TEST_REPO:
            logger.info("Indexing repo %s branch %s path %s (%d dir2license and %d file2features)",
                        repo_name, branch, branch_path, len(dir2license), len(file2features))
        else:
            logger.info("Dumping features in repo %s branch %s path %s (%d dir2license and %d file2features)",
                        repo_name, branch, branch_path, len(dir2license), len(file2features))

        # enable profiling if requested
        if not main.TEST_REPO and profiler:
            profiler.enable()

        # create database
        results = build_db(main=main, branch_details=branch_details, dir2license=dir2license,
                           file2features=file2features)
        if results:
            count += 1

        # stop profiling if on
        if not main.TEST_REPO and profiler:
            profiler.disable()
            profiler.dump_stats(main.PROFILE_DUMP_FILE_PREFIX +
                                "%s_%s_%s_build_db.cprof" % (os.getpid(), repo_id, branch))

    # all done
    if count:
        return 1, count
    else:
        return 0, 0


###########################################################
# Indexer
###########################################################
def run(main, argv):
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger
    signature.logger = main.logger
    signature.stats_logger = main.stats_logger

    if len(argv) != 2:
        logger.error('expects two args')
        exit(1)

    # if we are just testing this repo
    if argv[0] == 'dump' or argv[0] == 'stats':
        main.TEST_REPO = True
    if argv[0] == 'stats':
        main.STATS = True

    if main.TEST_REPO and not stats_logger:
        logger.error("Enable STATS Logger in config to dump features!")
        exit(1)

    # prepare repo list
    root_repo_path, repo_list = fetch_and_filter_repo_list(main=main, url_or_path=argv[1])
    if main.SHUFFLE_INPUT:
        random.shuffle(repo_list)

    # start scanning
    if repo_list:

        # how many repos
        count = len(repo_list)
        logger.info("Request to index %s repos", count)

        # register signal handler
        signal = utils.Signal()
        signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

        # track progress
        if main.TEST_REPO:
            pb = utils.Progressbar('Testing repos: ', count)
        else:
            pb = utils.Progressbar('Indexing repos: ', count)
        pb.start()

        # create root repo dir if doesn't exist
        ts = None
        if not root_repo_path:
            try:
                ts = time.strftime('%Y_%m_%d_%H_%M_%S')
                root_repo_path = "/tmp/" + os.path.basename(argv[1]) + "_" + ts
                os.mkdir(root_repo_path)
            except Exception as e:
                logger.error("Error creating root_repo_path %s: %s", root_repo_path, str(e))
                return

        # if we are testing
        test = None
        if main.STATS:
            test = 'stats'
        elif main.TEST_LIB:
            test = 'dump'

        # if requested parallelism
        if main.QUEUING and main.QUEUING == "Celery":
            from celery import group
            from celery_tasks import native_indexing_worker

            # group jobs
            job = group(native_indexing_worker.s(repo_path=root_repo_path, repo_id=item, branch=branch, test=test)
                        for item, branch in repo_list)
            result = job.apply_async()

            # track worker progress
            completed = 0
            while (result.waiting()):
                completed += result.completed_count()
                if completed < count:
                    pb.update(completed)
                time.sleep(2)

            # all done
            pb.finish()
            count = completed

        else:  # non-parallel instance

            count = 0

            # scan loop
            for item, tag in repo_list:

                # check for interruption
                if signal.caught():
                    break

                # item is a tuple <repo id, repo url>
                if not item.isdigit() or int(item) < 0:
                    repo_id, repo_name = item.split(",")
                else:
                    repo_id = item

                if main.TEST_REPO:
                    pb.msg('Testing {0} '.format(repo_id))
                else:
                    pb.msg('Indexing {0} '.format(repo_id))

                # scan repo; already filtered
                if index_repo(main, root_repo_path, item, branch=tag):
                    count += 1

                # update progressbar
                pb.update(count)

            if not signal.caught():
                pb.finish()

        # delete root_repo_path
        if ts:
            shutil.rmtree(root_repo_path)

        # log number of repos indexed
        total = main.nrc.handle().get("repos")
        if total:
            if main.TEST_REPO:
                logger.critical("Indexed a total of %s repos (tested %d)", total, count)
            else:
                logger.critical("Indexed a total of %s repos (new: %d)", total, count)
