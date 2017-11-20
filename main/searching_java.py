#!/usr/bin/env python

import os
import shutil
import tempfile
import time
import operator
from collections import Counter
from itertools import izip
from ast import literal_eval

import utils
import signature_java
from common import get_rkey
from version_db import search_version_db
from centroid import search_centroid_db, get_typed_centroid_key, get_centroid_string
from process_result import get_repo_groups
from signature_java import (get_all_classes_summary, get_input_list, get_no_package_func,
                            get_obfuscation_resilient_func, get_class_string)
from signature_java_constants import (JOB_CHUNK, skip_set, framework_prefix, leaf_nodes, internal_nodes)


###########################################################
# init state
###########################################################
logger = None
stats_logger = None
MIN_MATCHING_SCORE = None
MIN_LOW_LEVEL_MATCHING_SCORE = None


def get_featcnt(featcounters, search_features):
    featcnt = 0
    if 'strings' in search_features:
        featcnt += featcounters['strcnt']
    if 'classes' in search_features:
        featcnt += featcounters['classcnt']
    if 'normclasses' in search_features:
        featcnt += featcounters['normclasscnt']
    if 'centroids' in search_features:
        featcnt += featcounters['centroidcnt']
    return featcnt


def get_uniqfeatcnt(featcounters, search_features):
    uniqfeatcnt = 0
    if 'strings' in search_features:
        uniqfeatcnt += featcounters['uniqstrcnt']
    if 'classes' in search_features:
        uniqfeatcnt += featcounters['uniqclasscnt']
    if 'normclasses' in search_features:
        uniqfeatcnt += featcounters['uniqnormclasscnt']
    if 'centroids' in search_features:
        uniqfeatcnt += featcounters['uniqcentroidcnt']
    return uniqfeatcnt


#####################################################################
# Lookup by features and aggregate matching items
# Time Complexity : O(Number of features * Number of matching items)
#####################################################################
def get_matches(main, redis, input_path, repo_matches, features_map, feat2refcnt, matched_set, level, tree=None):

    num_matched_features = 0
    matches = {}  # maps matched parent to all child features

    # only used when level == 0
    item_list = []

    # get matches, and set of items
    logger.info("get matches and set of items")
    feature_list = features_map.keys()

    redis_pipe = main.jrc.pipeline()
    for feature in feature_list:
        redis_pipe.hgetall(feature)
    feature_items_list = redis_pipe.execute()

    # iterate over features to looking them up to find matching items
    logger.info("finished querying %s features for matched items", len(feature_list))
    for feature, matched_items in izip(feature_list, feature_items_list):

        if not matched_items or len(matched_items) == 0:
            # orphaned features doesn't have matched items
            continue

        num_matched_features += 1
        logger.debug("feature %s matched items: %s", feature, matched_items)

        # skip popular feature
        if 'refcnt' in matched_items and int(matched_items['refcnt']) > main.MAX_PER_STR_MATCHING_REPO_COUNT:
            continue

        feature_type, _ = feature.split('-', 1)
        # iterate over all matching items, ranking them by their matching scores
        for item, item_value in matched_items.items():
            if item == 'refcnt':
                feat2refcnt[feature] = int(item_value)

            # skip if not needed or same as parent
            if item in skip_set or item == feature:
                continue

            item_type, _ = item.split('-', 1)
            if item_type == 'repo':

                feature_score = features_map[feature]['feature_score']
                feature_normscore = features_map[feature]['feature_normscore']
                feature_freq = features_map[feature]['featfreq']
                feature_count = features_map[feature]['featcnt']
                if feature_normscore < MIN_MATCHING_SCORE:
                    logger.info("filtered repo %s due to low matching score %s", item, feature_normscore)
                    continue

                if feature_count < main.MIN_MATCHING_REPO_FEATURE_COUNT:
                    logger.info("filtered repo %s due to low leaf feature count %s", item, feature_count)
                    continue

                logger.info("input %s matched repo %s from feature %s with score %f and normscore %f",
                            input_path, item, feature, feature_score, feature_normscore)
                # update repo matches
                repo_matches[item] = (feature_freq, feature_count, feature_score, feature_normscore)
                # record the mapping from feature to repo
                tree.setdefault(item, {})
                tree[item][feature] = feature_freq
                continue

            else:
                # update parent to children mapping, as matches
                if level == 0 and item not in matches:
                    redis_pipe.hlen(get_rkey(item))
                    item_list.append(item)

                # update parent to children mapping
                matches.setdefault(item, set())
                matches[item].add(feature)

    matched_set.update(set(matches.keys()))

    ############################################################
    # filter the matched files, if the matched number ratio of children is smaller than a certain amount
    ############################################################
    if level == 0:
        item_featcnt_list = redis_pipe.execute()
        item2featcnt = {}
        for item, item_featcnt in izip(item_list, item_featcnt_list):
            # item_uniq_cnt may not be available
            item2featcnt[item] = int(item_featcnt) if item_featcnt else 0

        old_matches_count = len(matches)
        min_pct = main.MIN_PERCENT_MATCH['java'] if isinstance(main.MIN_PERCENT_MATCH, dict) else main.MIN_PERCENT_MATCH
        matches = {item: matched_children for item, matched_children in matches.items()
                   if item2featcnt[item] > 0 and float(len(matched_children)*100)/item2featcnt[item] >= min_pct}
        new_matches_count = len(matches)
        logger.info("filtered %d file matches into %d file matches using ratio filtering", old_matches_count, new_matches_count)

    logger.info("finished computing matches")
    return num_matched_features, matches


def get_children_from_tree(parent, tree):
    return [child for child in tree[parent].keys() if '-' in child]


###########################################################
# Lookup by matched items to find unmatched items
###########################################################
def get_unmatches(main, redis, matches, tree, feat2refcnt):
    """
    Before calling build_unmatched_tree, we want to finish all the redis queries using pipeline.
    We first get all the children for first-seen parents, then query the featcnt for both the parent
    and first-seen children. The featcnt are computed if not present. This guarantees that featcnt
    is available for every possible parent and child.

    We also maintain the parent to all_children mapping, by querying tree or redis (if parent not present),
    this mapping are used in build_unmatched_tree to iterate for featfreq
    """

    parent_list = []
    redis_pipe = main.jrc.pipeline()

    # get all children for all parent, this is used in build_unmatched_tree for iteration purpose
    logger.debug("get all children for all non-file parent, this is used in build_unmatched_tree for iteration purpose")

    # separate list for all parents despite their availabilty in the tree{}
    parent2all_children = {}

    for parent, children in matches.items():
        parent_type, parent_id = parent.split('-', 1)
        if parent_type != "repo":
            if parent not in tree:
                # get all children
                parent2all_children.setdefault(parent, [])
                tree.setdefault(parent, {})
                tree[parent]['featcnt'] = 0
                parent_list.append(parent)
                redis_pipe.hgetall(get_rkey(parent))
            else:
                parent2all_children[parent] = get_children_from_tree(parent, tree)
    members_list = redis_pipe.execute()

    # separate list querying refcnt/license for all children
    refcnt_query_feature_list = []

    # parent is definitely not in tree, because they were already filtered in the previous loop
    # get feature frequency for all child to parent mappings!
    logger.debug("get feature frequency for unknown mappings, including parent and children")
    for parent, members in izip(parent_list, members_list):
        if parent not in feat2refcnt:
            feat2refcnt.setdefault(parent, {})  # avoid duplicate redis queries
            refcnt_query_feature_list.append(parent)
            redis_pipe.hget(parent, 'refcnt')
        else:
            tree[parent]['refcnt'] = feat2refcnt[parent]

        # XXX optimization: prefetch all members' featcnt
        for member, member_featcounters in members.items():

            parent2all_children[parent].append(member)

            if member == parent:
                continue

            # TODO: single list for refcnt, featcnt
            # members may be in the tree, or may have been queried
            member_type, _ = member.split('-', 1)
            if member_type in leaf_nodes:
                # optimization: cache featfreq/featcnt for leaf nodes here!
                member_featcnt = int(member_featcounters)
                member_uniqfeatcnt = 1
                if member not in matches[parent]:
                    # negative featfreq = featcnt for unmatched feature
                    tree[parent][member] = -1 if main.USE_UNIQ_FEATURES_FOR_TF else -member_featcnt
                else:
                    # positive featfreq = featcnt for matched feature
                    tree[parent][member] = 1 if main.USE_UNIQ_FEATURES_FOR_TF else member_featcnt
            elif member_type in internal_nodes:
                member_featcounters = literal_eval(member_featcounters)
                member_featcnt = get_featcnt(member_featcounters, main.search_features)
                member_uniqfeatcnt = get_uniqfeatcnt(member_featcounters, main.search_features)
            else:
                logger.error("unexpected type of member %s", member_type)

            # optimization: do not query redis, get featcnt for parent by adding children featcnt
            tree[parent]['featcnt'] += member_uniqfeatcnt if main.USE_UNIQ_FEATURES_FOR_TF else member_featcnt

            # build list to prefetch refcnt for all members
            if member not in feat2refcnt:
                feat2refcnt.setdefault(member, {})  # avoid duplicate redis queries
                refcnt_query_feature_list.append(member)
                redis_pipe.hget(member, 'refcnt')

            # cache 'featcnt'
            tree.setdefault(member, {})
            tree[member]['featcnt'] = member_uniqfeatcnt if main.USE_UNIQ_FEATURES_FOR_TF else member_featcnt
            if member in feat2refcnt:
                tree[member]['refcnt'] = feat2refcnt[member]

    # fill in refcnt for unknown items
    logger.info("fill in refcnt for unknown items")
    refcnt_list = redis_pipe.execute()
    for feature, refcnt in izip(refcnt_query_feature_list, refcnt_list):
        # any feature that is not in tree or feat2attributes has been resolved!
        tree[feature]['refcnt'] = feat2refcnt[feature] = int(refcnt) if refcnt else 0

    # iterate over matching nodes looking them up to find unmatched ones
    logger.info("iterate over matching nodes looking them up to find unmatched ones")
    for parent, children in matches.items():
        parent_type, parent_id = parent.split('-', 1)
        if parent_type != "repo":
            build_unmatched_tree(main, redis, parent, children, parent2all_children[parent], tree)


def build_unmatched_tree(main, redis, parent, known_children, all_children, tree,):

    parent_type, parent_id = parent.split('-')
    parent_id = long(parent_id)

    # From each child, we walk up.
    # The featcnt for each parent must already be available here, so we need to walk from the child to parents
    # to update their feature frequency.
    #
    # 1. all the parents and their children are mapped to featcnt now!
    # 2. parent to children relationship is cached in all_children!
    # 3. the parent shows up meaning that the featfreq has changed, so we re-compute
    #if parent_type == "file":
    logger.debug("parent %s has %d known and %d unknown children total %d",
                 parent, len(known_children), len(all_children) - len(known_children), len(all_children))

    # reset parent featfreq
    tree[parent]['featfreq'] = 0

    for child in all_children:

        child_type, child_id = child.split('-', 1)
        if child_type in leaf_nodes:
            # if this child node has been discovered before, it may be updated
            if child in tree[parent]:
                child_feature_freq = long(tree[parent][child])
            else:
                logger.error("unexpected child type %s", child_type)

        else:

            # if this child is somebody's parent
            if child not in tree:
                logger.error("child %s must be in the tree", child)
            else:
                # this child was mapped before, and it may be updated in the previous iteration, so load it again!
                if 'featfreq' in tree[child]:
                    child_feature_freq = long(tree[child]['featfreq'])
                else:
                    tree[child]['featfreq'] = 0
                    child_feature_freq = 0

        # matched/unmatched child features
        tree[parent][child] = child_feature_freq

        # matched parent features
        if child_feature_freq > 0:
            tree[parent]['featfreq'] += child_feature_freq

    logger.debug("parent type %s id %s children: %s", parent_type, parent_id, tree[parent])


###########################################################
# Get total num of items of a particular kind
###########################################################
def get_child_idf(main, redis, child, parents_type, tree, norm_idf=True):
    try:
        if 'refcnt' not in tree[child]:
            child_refcnt = redis.hget(child, 'refcnt')
            if not child_refcnt:
                return 0
            else:
                tree[child]['refcnt'] = int(child_refcnt)
        num_matching_parents = tree[child]['refcnt']
        if not num_matching_parents:
            raise Exception("failed to get matching parents")
        parents_type_cnt = parents_type + 'cnt'
        if parents_type_cnt not in tree:
            tree[parents_type_cnt] = int(redis.get(parents_type_cnt))
        total_num_parent_like_nodes = tree[parents_type_cnt]
        if not total_num_parent_like_nodes:
            raise Exception("failed to get parent like nodes")
        idf = utils.idf(float(total_num_parent_like_nodes), float(num_matching_parents))
        if norm_idf:
            idf /= utils.idf(float(total_num_parent_like_nodes), 1)
        return idf
    except Exception as e:
        logger.error("Failed to calculate idf for child %s parent type %s: %s", child, parents_type, str(e))
        return None


def filter_matches(main, redis, matches, tree, node2group, level):

    # fix the refcnt in tree based on SEARCH_SIMHASH_DISTANCE
    utils.fix_refcnt(main=main, feat2refcnt=tree, node2group=node2group, matches=matches, level=level, logger=logger)

    next_matches = {}
    for parent, children in matches.items():

        parent_type, parent_id = parent.split('-')
        if parent_type == "repo":
            logger.error("invalid parent %s. this shouldn't happened! ignoring!", parent)
            continue

        if parent not in tree:
            logger.warn("parent %s not found. ignoring", parent)
            continue

        parent_feature_count = tree[parent]['featcnt']
        match_count = tree[parent]['featfreq']

        logger.debug("parent %s num matched features (uniq matches %s) %s num total features: %s",
                     parent, match_count, len(tree[parent]), parent_feature_count)

        parent_score = 0.0
        parent_expected = 0.0

        # rank parents based on their score
        # tree maps:
        #       parent -> {child1: feature_freq, child2: feature_freq, ..., strcnt, strfreq}
        #       child1 -> {grandchild1: feature_freq, grandchild2: feature_freq, ..., strcnt, strfreq}
        # parent -> children, and child -> strcnt, strfreq, are used to compute the tfidf
        #
        # all child keys has a '-' in, they are 'dirs-, files-, strings-, classes-, normclasses-, centroids-' etc.
        children_to_check = get_children_from_tree(parent, tree)

        # prepare the values to use in grouped match
        if main.USE_GROUPED_MATCH:

            # prepare the matched str freq and func freq at matched file/dir level!
            if parent_type in internal_nodes:
                children_grouped_strfreq = 0
                children_grouped_normclassfreq = 0
                children_grouped_centroidfreq = 0
                if parent_type == 'files':
                    for child in children_to_check:
                        if tree[parent][child] > 0:
                            child_type, _ = child.split('-')
                            if child_type == 'strings':
                                children_grouped_strfreq += tree[parent][child]
                            elif child_type == 'normclasses':
                                children_grouped_normclassfreq += tree[parent][child]
                            elif child_type == 'centroids':
                                children_grouped_centroidfreq += tree[parent][child]
                            else:
                                logger.error("file %s has unexpected child type %s", parent, child)
                elif parent_type == 'dirs':
                    for child in children_to_check:
                        if 'grouped_strfreq' in tree[child]:
                            children_grouped_strfreq += tree[child]['grouped_strfreq']
                        if 'grouped_normclassfreq' in tree[child]:
                            children_grouped_normclassfreq += tree[child]['grouped_normclassfreq']
                        if 'grouped_centroidfreq' in tree[child]:
                            children_grouped_centroidfreq += tree[child]['grouped_centroidfreq']

                tree[parent]['grouped_strfreq'] = children_grouped_strfreq
                tree[parent]['grouped_normclassfreq'] = children_grouped_normclassfreq
                tree[parent]['grouped_centroidfreq'] = children_grouped_centroidfreq

            # grouped matches (featfreq, featcnt) works only when child is at file/dir level, i.e., when parent is at dir level!
            if parent_type == 'dirs':
                children_grouped_featcnt = 0
                children_grouped_featfreq = 0
                for child in children_to_check:
                    if 'grouped_featcnt' in tree[child] and 'grouped_featfreq' in tree[child]:
                        children_grouped_featcnt += tree[child]['grouped_featcnt']
                        children_grouped_featfreq += tree[child]['grouped_featfreq']
                    else:
                        # str/func -> file, no grouped_featfreq/featcnt
                        # file -> dir, file doesn't have grouped_featfreq/featcnt
                        # dir -> dir, must have grouped_featfreq/featcnt
                        children_grouped_featcnt += tree[child]['featcnt']
                        children_grouped_featfreq += tree[child]['featfreq']
                tree[parent]['grouped_featcnt'] = children_grouped_featcnt
                tree[parent]['grouped_featfreq'] = children_grouped_featfreq

        for child in children_to_check:

            if child in skip_set:
                continue

            child_type, child_id = child.split("-")
            child_id = long(child_id)

            if child not in tree[parent]:
                logger.warn("Child %s not found in matches parent %s. Ignoring!", parent)
                continue

            child_feature_freq = float(tree[parent][child])
            child_feature_count = float(tree[child]['featcnt']) if child in tree else abs(child_feature_freq)
            # if nothing matches
            if child_feature_freq == 0:
                if child_type in leaf_nodes:
                    logger.error("Unexpected! feature freq is zero for a feature %s. Ignoring!", child_type)
                    continue
                else:
                    # expected number of features
                    # child_feature_freq = -float(tree[child]['featcnt'])
                    logger.debug("In the new score system, we don't subtract")

            # default grouped feat count/freq to actual value
            child_grouped_feature_count = child_feature_count
            child_grouped_feature_freq = child_feature_freq
            if main.USE_GROUPED_MATCH and parent_type == 'dirs':
                # if the matching ratio is low
                if child_type in internal_nodes:
                    # strfreq and funcfreq and funcnamefreq
                    child_grouped_strfreq = tree[child]['grouped_strfreq'] if 'grouped_strfreq' in tree[child] else 0
                    child_grouped_normclassfreq = tree[child]['grouped_normclassfreq'] if 'grouped_normclassfreq' in tree[child] else 0
                    child_grouped_centroidfreq = tree[child]['child_grouped_centroidfreq'] if 'child_grouped_centroidfreq' in tree[child] else 0

                    # featcnt and featfreq
                    if 'grouped_featcnt' in tree[child] and 'grouped_featfreq' in tree[child]:
                        child_grouped_feature_count = tree[child]['grouped_featcnt']
                        child_grouped_feature_freq = tree[child]['grouped_featfreq']
                    else:
                        pass

                    child_match_ratio = float(
                        child_grouped_feature_freq) / child_grouped_feature_count if child_grouped_feature_count else 0

                    # Rule 1: if the child is a source file (not header), and has no function matches, then exclude it
                    # all file should have filetype!
                    # Doesn't apply to Java

                    # Rule 2: if the child has license file
                    # Doesn't apply to Java

                    # Rule 3: if the child has much higher refcnt than the rest of the child
                    if child_type in main.GROUPED_NODE_TYPES and len(children_to_check) >= 2:
                        # for each child, compare it with all other child in the same folder
                        import numpy as np
                        # TODO: should we consider the unmatched other children or all the other children?!
                        # [tree[other_child]['refcnt'] for other_child in children_to_check if other_child != child and tree[other_child]['featfreq'] <= 0]
                        other_children_avg_refcnt = np.mean(
                            [tree[other_child]['refcnt'] for other_child in children_to_check if other_child != child])
                        if tree[child]['refcnt'] >= other_children_avg_refcnt * main.MAX_GROUPED_REFCNT_RATIO:
                            # NOTE: the child is too frequent, so we consider it as third party dir and exclude it
                            tree[parent]['grouped_featcnt'] -= child_grouped_feature_count
                            tree[parent]['grouped_featfreq'] -= child_feature_freq
                            tree[parent]['grouped_strfreq'] -= child_grouped_strfreq
                            tree[parent]['grouped_normclassfreq'] -= child_grouped_normclassfreq
                            tree[parent]['grouped_centroidfreq'] -= child_grouped_centroidfreq
                            logger.debug("skipped child %s when matching parent %s due to high refcnt: %s (avg of others %s)",
                                         child, parent, tree[child]['refcnt'], other_children_avg_refcnt)
                            continue

                    # Rule 4: if the child has a low match ratio (use GROUPED_NODE_TYPES to control the types of nodes to apply this filtering)
                    # Doesn't apply to Java
                    # if child_type in main.GROUPED_NODE_TYPES and child_match_ratio <= main.MIN_GROUPED_PERCENT_MATCH:
                    #     tree[parent]['grouped_featcnt'] -= child_grouped_feature_count
                    #     tree[parent]['grouped_featfreq'] -= child_feature_freq
                    #     tree[parent]['grouped_strfreq'] -= child_grouped_strfreq
                    #     tree[parent]['grouped_normclassfreq'] -= child_grouped_normclassfreq
                    #     tree[parent]['grouped_centroidfreq'] -= child_grouped_centroidfreq
                    #     logger.debug("skipped child %s when matching parent %s due to low matching ratio: %s",
                    #                  child, parent, child_match_ratio)
                    #     continue

            # use tfidf metric to derive feature weight
            if not parent_feature_count:
                child_idf = None
                child_score = 0
                child_expected = 0
            else:
                child_idf = get_child_idf(main, redis, child, parent_type, tree)
                if main.USE_GROUPED_MATCH and parent_type == 'dirs':
                    child_score = child_grouped_feature_freq * child_idf
                    child_expected = child_grouped_feature_count * child_idf
                else:
                    child_score = child_feature_freq * child_idf
                    child_expected = child_feature_count * child_idf

            logger.debug("parent id %s type %s child id %s type %s total features %s tf: %f idf: %f score %f",
                         parent_id, parent_type, child_id, child_type, parent_feature_count, child_feature_freq,
                         child_idf, child_score)

            # track parent score
            parent_score += child_score if child_score >= 0 else 0
            parent_expected += child_expected

        parent_normscore = float(parent_score) / parent_expected if parent_expected else 0

        if parent_normscore > MIN_LOW_LEVEL_MATCHING_SCORE:
            logger.debug("parent id %s type %s score %f normscore %f", parent_id, parent_type, parent_score,
                         parent_normscore)
            if main.USE_GROUPED_MATCH and parent_type == 'dirs':
                logger.debug("parent id %s type %s score %f normscore %f", parent_id, parent_type, parent_score,
                             parent_normscore)
                next_matches[parent] = {'featcnt': long(tree[parent]['grouped_featcnt']),
                                        'featfreq': long(tree[parent]['grouped_featfreq']),
                                        'feature_score': parent_score, 'feature_normscore': parent_normscore}

            else:
                next_matches[parent] = {'featcnt': long(tree[parent]['featfreq']),
                                        'featfreq': long(tree[parent]['featcnt']),
                                        'feature_score': parent_score, 'feature_normscore': parent_normscore}

    return next_matches


###########################################################
# Lookup items by features
#
# For each leaf feature, we find the matching files (items). Then from files, we find
# the matching directories, until we find the repos.
# 1. For each feature, we need feature_score, refcnt
# 2. For each item, we need uniqfeatcnt, refcnt and the matched children, vs. unmatched children
#
# Below is the logic
# - features -> files
#     - tfidf(features) = 1 / #uniqfeatcnt * #files/#files containing string
#         - for computation, we need to save
#             - #uniqfeatcnt per file (featcnt)
#             - #files containing string (frequency)
#     - unmatched tfidf(features) = -1 / #uniqfeatcnt * #files/#files containing string
#         - the same as above
# - files -> dirs, dirs -> dirs
#     - for a file, we could have its score precomputed
#     - for a dir, tfidf(files) = #uniq_matched_feat_cnt/#uniqfeatcnt * #dirs/#dirs containing file
#         - for computation, we need to save
#             - #uniq_matched_feat_cnt
#             - #uniqfeatcnt per dir
#             - #dirs containing file
#     - unmatched tfidf(files) = 1-#uniq_matched_feat_cnt/#uniqfeatcnt * #dirs/#dirs containing file
#         - the same as above
# - dirs -> repo
# - we need to normalize idf, to avoid high score of deep repos
# - we need to save the precomputed scores for each file/dir, to avoid repeated computation
###########################################################
def search_app(main, redis, input_path, features_map, search_features):

    # tree: maps node id to {'featcnt': xxx, 'featfreq': xxx, 'child1': xxxfreq, 'child2': xxxfreq,
    #                        'grouped_featcnt': xxx, 'grouped_featfreq': xxx,
    #                        'grouped_funcfreq': xxx, 'grouped_strfreq': xxx, 'grouped_funcnamefreq': xxx,
    #                        'refcnt': xxx, 'filetype': xxx, 'license': xxx}, also has key files, dirs, repos
    # matches: maps parent id, to all matched children ids
    # repo_matches: maps repo id to feature score
    # feat2refcnt: maps redis key to refcnt value, this is used to reduce queries to redis
    # matches_set: record the items that have been matched before, to avoid reconsidering, (this is a temporary bug fix to the infinite loop problem)
    tree = {}
    repo_matches = {}
    feat2refcnt = {}
    matched_set = set()
    node2group = {}

    # note: if we use item2uniqfeatcnt as normalization term, then the tf of children doesn't sum to 1
    time_point = time.time()
    level = 0
    # XXX hack: the level is a mandatory temporary hack to fix the infinite loop problem. the node changed
    # attribute doesn't seem to work here.
    while features_map and level < 1000:

        # Phase 1: lookup features
        try:
            num_matched_features, matches = get_matches(main=main, redis=redis, input_path=input_path,
                                                        repo_matches=repo_matches, features_map=features_map,
                                                        feat2refcnt=feat2refcnt, matched_set=matched_set,
                                                        level=level, tree=tree)
        except Exception as e:
            logger.error("Error computing matches from features at level %d, error %s", level, str(e))
            return None

        if stats_logger:
            new_time_point = time.time()
            stats_logger.info("time elapsed for finding %d matches from %d features at level %d: %s seconds",
                              len(matches), len(features_map), level, new_time_point - time_point)
            time_point = new_time_point

        logger.info("num features: %d, num matched features: %d, num matched parents: %d",
                    len(features_map), num_matched_features, len(matches))
        if len(matches) == 0:
            break

        # Phase 2: build unmatched tree
        try:
            get_unmatches(main=main, redis=redis, matches=matches, tree=tree, feat2refcnt=feat2refcnt)
        except Exception as e:
            logger.error("Error computing unmatches from matches at level %d, error %s", level, str(e))
            return None

        if stats_logger:
            new_time_point = time.time()
            stats_logger.info("time elapsed for building unmatched features for %d parents at level %d: %s seconds",
                              len(matches), level, new_time_point - time_point)
            time_point = new_time_point

        # Phase 3: filter matches
        try:
            features_map = filter_matches(main, redis, matches, tree, node2group, level)
        except Exception as e:
            logger.error("Error filter matches from matches: %s, error %s", matches, str(e))
            return None

        if stats_logger:
            new_time_point = time.time()
            stats_logger.info("time elapsed for filtering features for %d matches in to %d features at level %d: %s seconds",
                              len(matches), len(features_map), level, new_time_point - time_point)
            time_point = new_time_point

        # next round
        logger.debug("next features: %s", features_map)
        level += 1

    # we have a list of matches
    if len(repo_matches):
        logger.info("lib %s using %s features matched repos: %s", input_path, search_features, sorted(repo_matches.items(), key=operator.itemgetter(1), reverse=True))
    else:
        logger.info("lib %s using %s features didn't match", input_path, search_features)

    return repo_matches, tree


def get_uniq_features(redis, typed_key):
    leaf_nodes_set = set()

    # use bfs to get the list of files that need to be union-ed
    visited, queue = set(), [get_rkey(typed_key)]
    while queue:
        vertex = queue.pop(0)
        vertex_type = vertex.rsplit('-', 1)[0]
        if vertex_type == "r-dirs":
            # vertex can map to itself, and we ignore such mappings
            if vertex not in visited:
                visited.add(vertex)
                # Use reverse key for go down purpose
                children = set([get_rkey(item) for item in redis.hkeys(vertex)])
                queue.extend(children - set(visited))
        elif vertex_type == "r-files":
            leaf_nodes_set.add(vertex)
        else:
            raise Exception("bfs on unexpected vertex type: %s" % vertex_type)

    # union the features to get uniq feature count
    str_features = []
    classes_features = []
    normclass_features = []
    centroid_features = []
    for leaf_feature in redis.sunion(list(leaf_nodes_set)):
        if leaf_feature.startswith("strings-"):
            str_features.append(leaf_feature)
        elif leaf_feature.startswith("classes-"):
            classes_features.append(leaf_feature)
        elif leaf_feature.startswith("normclasses-"):
            normclass_features.append(leaf_feature)
        elif leaf_feature.startswith("centroids-"):
            centroid_features.append(leaf_feature)

    return str_features, classes_features, normclass_features, centroid_features


def get_match_score(main, redis, input_path, features_map, features_type, libraries):
    # compute the score for features matching libraries, this function does a very naive feature set comparison
    matches = {}
    logger.info("Getting match score for libraries: %s", libraries)
    for software_id, repo_info in libraries.items():
        # The version of repos should be reverse sorted here, we simply pick the first one
        version, repo_id, featfreq, featcnt, score, normscore = repo_info[0]
        reversable_id = None
        for key, _ in redis.hgetall(repo_id).items():
            if key.startswith("dirs-") or key.startswith("files-"):
                reversable_id = key
        str_features, classes_features, normclass_features, centroid_features = get_uniq_features(redis, reversable_id)
        if features_type == "classes":
            to_compare_features = classes_features
        elif features_type == "strings":
            to_compare_features = str_features
        elif features_type == "normclasses":
            to_compare_features = normclass_features
        elif features_type == "centroids":
            to_compare_features = centroid_features
        else:
            raise Exception("Unexpected features_type: %s" % features_type)

        matched_feature_set = set(to_compare_features) & set(features_map.keys())
        if len(matched_feature_set) > 0:
            matching_score = float(len(matched_feature_set)) / len(to_compare_features)
        else:
            matching_score = 0

        if matching_score < MIN_MATCHING_SCORE:
            logger.info("filtered repo %s due to low matching score %s", repo_id, matching_score)
        else:
            matches.setdefault(software_id, [])
            matches[software_id].append((version, repo_id, featfreq, featcnt, matching_score))

    return matches


def get_software_id(main, redis, matches, check_license=True):
    """
    Query redis database to get software information. Query OSS database to get license information.

    :param main: detector object
    :param redis: access to the indexing database
    :param matches: dict, maps repo id -> (freq, cnt, score, normscore) tuple
    :param check_license: whether to check license or not
    :return:
    """
    software2repo_id = {}  # maps software to repo id
    nongpl_software2repo_id = {}  # maps software to nongpl repo_id
    gpl_software2repo_id = {}  # maps software to gpl repo_id
    lgpl_software2repo_id = {}  # maps lgpl software to repo id, this is a subset of software2repo_id
    software_id2license = {}  # cache the postgres license query
    # Version 2.0: rank the matches by unnormalized score, because it is intended for ranking!
    # for software_pathhash, score_tuple in sorted(matches.items(), key=lambda x: x[1][-2], reverse=True):
    for software_pathhash, score_tuple in matches.items():
        featfreq, featcnt, score, normscore = score_tuple
        software_id = redis.hget(software_pathhash, 'software_id')
        version = redis.hget(software_pathhash, 'version')
        if not software_id or software_id == "None":
            logger.info("input_id %s doesn't have software_id: %s, using software_path(input_path) instead!", software_pathhash, redis.hgetall(software_pathhash))
            software_path = redis.hget(software_pathhash, 'input_path')
            software2repo_id.setdefault(software_path, [])
            software2repo_id[software_path].append((version, software_pathhash, featfreq, featcnt, score, normscore))
        else:
            software2repo_id.setdefault(software_id, [])
            software2repo_id[software_id].append((version, software_pathhash, featfreq, featcnt, score, normscore))

            # Check license if instructed
            if check_license:
                if software_id not in software_id2license:
                    software_id2license[software_id] = get_license(oss_db=main.jdb, lib_id=software_id)
                if software_id2license[software_id] == 'lgpl':
                    lgpl_software2repo_id.setdefault(software_id, [])
                    lgpl_software2repo_id[software_id].append((version, software_pathhash, featfreq, featcnt, score, normscore))
                elif software_id2license[software_id] == 'gpl':
                    gpl_software2repo_id.setdefault(software_id, [])
                    gpl_software2repo_id[software_id].append((version, software_pathhash, featfreq, featcnt, score, normscore))
                elif software_id2license[software_id] == 'nongpl':
                    nongpl_software2repo_id.setdefault(software_id, [])
                    nongpl_software2repo_id[software_id].append((version, software_pathhash, featfreq, featcnt, score, normscore))

    return software2repo_id, nongpl_software2repo_id, gpl_software2repo_id, lgpl_software2repo_id


def get_license(oss_db, lib_id):
    # lib_id, group_id, artifact_id
    query_result = oss_db.query("license_abbrs", lib_id=lib_id)
    try:
        logger.info("license string for lib_id %s is %s", lib_id, query_result)
        if 'lgpl' in str(query_result).lower():
            return 'lgpl'
        elif 'gpl' in str(query_result).lower():
            return 'gpl'
        else:
            return 'nongpl'
    except Exception as e:
        logger.error("Error querying oss_db: lib_id %s, results %s, error %s", lib_id, query_result, str(e))

    return None


###########################################################
# Lookup all kinds of features, and flag violation
###########################################################
def search_items(main, input_path, input_type, outdir, return_features=False):
    summary_proto = get_all_classes_summary(input_path=input_path, outdir=outdir, input_type=input_type, main=main)

    logger.info("Searching input %s", input_path)
    used_non_application_class_set = set()
    for class_pair in summary_proto.class_pairs:
        if (not class_pair.classname2_is_application_class) and (class_pair.classname2.startswith(framework_prefix)):
            used_non_application_class_set.add(class_pair.classname2)

    if main.TEST_REPO:
        for class_proto in summary_proto.classes:
            string_const = []
            function_name = []
            normfunction_name = []
            for method_proto in class_proto.methods:
                for string in method_proto.string_constants:
                    # stats
                    string_const.append(string)
                # stats
                function_name.append(get_no_package_func(
                    method_proto=method_proto, non_application_classes=used_non_application_class_set))
                # stats
                normfunction_name.append(get_obfuscation_resilient_func(
                    method_proto=method_proto, non_application_classes=used_non_application_class_set))

            normclass_name = get_class_string(normfunction_name, unique=False)

            if stats_logger:
                # permission is hard to get, ignoring now!
                stats_logger.info("class %s -->\nstring constants (%d): %s\nmethod names (%d): %s\nnorm method names (%d): %s\n"
                                  "norm class name: %s",
                                  class_proto.class_name, len(string_const), string_const,
                                  len(function_name), function_name, len(normfunction_name), normfunction_name, normclass_name)
    else:
        # build feature map
        strs_to_search = []
        classes_to_search = []
        normclasses_to_search = []
        centroids_to_search = []
        centroid_features_map_original = {}  # used for deduplication, and version pinpointing!
        feat2plain = {}  # used for printing and comparison in version pinpointing!
        # maps class id to features, and features key to class ids
        feat2classes = {}
        class2feats = {}

        for class_proto in summary_proto.classes:
            function_name = []  # used for computing class name
            normfunction_name = []  # used for computing norm class name
            class_id = class_proto.class_name
            class2feats.setdefault(class_id, set())
            for method_proto in class_proto.methods:
                # type-$md5(str-$string)
                for str_const in method_proto.string_constants:
                    string_key = "strings-" + str(utils.get_key(main, str_const))
                    strs_to_search.append(string_key)
                    feat2plain.setdefault(string_key, str_const)
                    feat2classes.setdefault(string_key, [])
                    feat2classes[string_key].append(class_id)
                    class2feats[class_id].add(string_key)
                # Version 2.0:
                function_name.append(get_no_package_func(
                    method_proto=method_proto, non_application_classes=used_non_application_class_set))
                normfunction_name.append(get_obfuscation_resilient_func(
                    method_proto=method_proto, non_application_classes=used_non_application_class_set))

                if method_proto.HasField('centroid') and method_proto.HasField('centroid_with_invoke'):
                    # The processing of basic blocks for some methods fails due to soot bugs, therefore, centroid is
                    # not always available!
                    centroid_string = get_centroid_string(centroid=method_proto.centroid,
                                                          centroidinvoke=method_proto.centroid_with_invoke)
                    centroid_key = get_typed_centroid_key(main=main, centroid=method_proto.centroid,
                                                          centroidinvoke=method_proto.centroid_with_invoke)
                    feat2plain.setdefault(centroid_key, centroid_string)
                    feat2classes.setdefault(centroid_key, [])
                    feat2classes[centroid_key].append(class_id)
                    class2feats[class_id].add(centroid_key)
                    if centroid_key not in centroid_features_map_original:
                        centroid_features_map_original.setdefault(centroid_key, 0)
                        centroids_to_search.append((method_proto.centroid, method_proto.centroid_with_invoke))
                    centroid_features_map_original[centroid_key] += 1
            # handle class feature
            class_string = get_class_string(function_name, unique=False)
            class_key = "classes-" + str(utils.get_key(main, class_string))
            classes_to_search.append(class_key)
            feat2plain.setdefault(class_key, class_string)
            feat2classes.setdefault(class_key, [])
            feat2classes[class_key].append(class_id)
            class2feats[class_id].add(class_key)
            # handle normalized class feature
            normclass_string = get_class_string(normfunction_name, unique=False)
            normclass_key = "normclasses-" + str(utils.get_key(main, normclass_string))
            normclasses_to_search.append(normclass_key)
            feat2plain.setdefault(normclass_key, normclass_string)
            feat2classes.setdefault(normclass_key, [])
            feat2classes[normclass_key].append(class_id)
            class2feats[class_id].add(normclass_key)

        if 'centroids' in main.search_features:
            start_querying_centroid = time.time()
            start_centroid_count = len(centroids_to_search)
            centroids_to_search = search_centroid_db(main=main, centroid_tuple_list=centroids_to_search,
                                                     cdd_range=main.MAX_METHOD_DIFFERENCE_DEGREE,
                                                     max_result_count=main.MAX_CENTROID_RESULT_COUNT, logger=logger)
            logger.info("found %d similar centroid from %d centroids", len(centroids_to_search), start_centroid_count)
            if stats_logger:
                stats_logger.info("time elapsed for %s, found %d similar centroid from %d centroids: %0.2f seconds",
                                  input_path, len(centroids_to_search), start_centroid_count, time.time() - start_querying_centroid)
        else:
            centroids_to_search = centroid_features_map_original

        str_features_map = {k: v for k, v in Counter(strs_to_search).items()}
        class_features_map = {k: v for k, v in Counter(classes_to_search).items()}
        normclass_features_map = {k: v for k, v in Counter(normclasses_to_search).items()}
        centroid_features_map = {k: v for k, v in Counter(centroids_to_search).items()}
        logger.info("input contains %d string features and %d class features and %d normclass features "
                    "and %d centroids features",
                    len(str_features_map), len(class_features_map), len(normclass_features_map),
                    len(centroid_features_map))

        if return_features:
            return str_features_map, class_features_map, normclass_features_map, centroid_features_map

        # Search by combination of features! test str + norm classes! str + centroids!
        # search_features_type = ['strings', 'normclasses'] or ['strings', 'centroids']
        search_features_map = get_combined_features_map(search_features=main.search_features,
                                                        str_features_map=str_features_map,
                                                        class_features_map=class_features_map,
                                                        normclass_features_map=normclass_features_map,
                                                        centroid_features_map=centroid_features_map)
        if not search_features_map:
            logger.error("no features found in %s!", input_path)
            return

        redis = main.jrc.handle()
        feat_matches, tree = search_app(main=main, redis=redis, input_path=input_path, features_map=search_features_map,
                                        search_features=main.search_features) if len(search_features_map) else None

        # check for compliance of GPL/LGPL policies
        violation_count = 0
        feat_matches_software = {}
        if not feat_matches:
            # nothing found
            logger.info("No string matches in %s, no violation detected!", input_path)
        else:
            # if string matched GPL software, then it is definitely a violation
            feat_matches_software, nongpl, gpl, lgpl = get_software_id(main, redis, feat_matches, check_license=True)

            feat_matches_software = {lib_id: sorted(versions, key=lambda x: x[-2], reverse=True) for lib_id, versions in feat_matches_software.items()}
            if main.USE_VERSION_DIFFERENCES:
                # feat_matches_software: maps software_id -> version matching details!
                start_querying_version_db = time.time()
                logger.info("Using version differences to find versions for %d softwares!", len(feat_matches_software))
                version_features = get_combined_features_map(
                    search_features=['strings', 'classes', 'normclasses', 'centroids'],
                    str_features_map=str_features_map, class_features_map=class_features_map,
                    normclass_features_map=normclass_features_map, centroid_features_map=centroid_features_map_original)
                feat_matches_versions = search_version_db(main=main, input_path=input_path, features=version_features,
                                                          matched_details=feat_matches_software, feat2plain=feat2plain,
                                                          language="java", searchfeat2classes=feat2classes,
                                                          classes2searchfeat=class2feats, logger=logger)
                logger.critical("TFIDF based ranking of versions are:\n%s", feat_matches_software)
                logger.critical("UNIQ FEATURE based ranking of versions are:\n%s", feat_matches_versions)
                if stats_logger:
                    stats_logger.info("time elapsed for searching unique feature took %0.2f seconds",
                                      time.time() - start_querying_version_db)

            # group the matched result based on the set of matched features
            if main.USE_GROUPED_RESULT:
                # grouped_repo_name_matches: maps full_name -> group id
                start_grouping_results = time.time()
                repo_groups, repo2matched_leaves, repo2matched_tree = get_repo_groups(
                    main=main, repo_matches=feat_matches_software, tree=tree, result_type="java", logger=logger)

                # print the set of matched features for each repo
                if main.VERBOSE:
                    for repo_name in feat_matches_software:
                        logger.info("repo %s matched features:\n%s", repo_name,
                                    sorted({feat: feat2plain[feat] for feat in repo2matched_leaves[repo_name]}.items(),
                                           key=lambda k: k[0]))
                        logger.info("repo %s matched tree:\n%s", repo_name, repo2matched_tree[repo_name])

                # store the repo groups info
                logger.info("repo groups are %s", repo_groups)
                main.rrc.handle().hset(input_path, 'repo_groups', repo_groups)
                main.rrc.handle().hset(input_path, 'repo_group_count', len(set(repo_groups.values())))
                if stats_logger:
                    stats_logger.info("time elapsed for grouping results took %0.2f seconds",
                                      time.time() - start_grouping_results)

            # limit the number of version per repo to write back, because they can be a lot, pick 5
            MAX_VERSION_COUNT = 5
            if main.USE_VERSION_DIFFERENCES:
                for lib_id, versions in feat_matches_versions.items():
                    # the versions are already sorted in version_db.py
                    if len(versions) > MAX_VERSION_COUNT:
                        versions = versions[:MAX_VERSION_COUNT]
                        feat_matches_versions[lib_id] = versions
                logger.critical("input %s matched repos: %s", input_path,
                                sorted(feat_matches_versions.items(), key=lambda k: (k[1][0][-1], k[1][0][-3]), reverse=True))
            else:
                for lib_id, versions in feat_matches_software.items():
                    if len(versions) > MAX_VERSION_COUNT:
                        versions = versions[:MAX_VERSION_COUNT]
                        feat_matches_software[lib_id] = versions
                logger.critical("lib %s matched repos: %s", input_path,
                                sorted(feat_matches_software.items(), key=lambda k: k[1][0][-2], reverse=True))

            for lib_id in feat_matches_software:
                # sort by cumulative TFIDF if no UNIQ feature is found
                if lib_id in gpl and lib_id not in lgpl:
                    violation_count += 1
                    if main.rrc:
                        if main.USE_VERSION_DIFFERENCES:
                            logger.critical("input %s is violating GPL of %s with score %s!", input_path, lib_id, feat_matches_versions[lib_id])
                            main.rrc.handle().hset(input_path, lib_id + '(gpl)', feat_matches_versions[lib_id])
                        else:
                            logger.critical("input %s is violating GPL of %s with score %s!", input_path, lib_id, feat_matches_software[lib_id])
                            main.rrc.handle().hset(input_path, lib_id + '(gpl)', feat_matches_software[lib_id])
                elif lib_id in nongpl:
                    if main.rrc:
                        if main.USE_VERSION_DIFFERENCES:
                            logger.critical("input %s is using non-GPL of %s with score %s!", input_path, lib_id,  feat_matches_versions[lib_id])
                            main.rrc.handle().hset(input_path, lib_id + '(nongpl)',  feat_matches_versions[lib_id])
                        else:
                            logger.critical("input %s is using non-GPL of %s with score %s!", input_path, lib_id, feat_matches_software[lib_id])
                            main.rrc.handle().hset(input_path, lib_id + '(nongpl)', feat_matches_software[lib_id])

            # if string/centroids/normclasses matched, then for the LGPL licensed software, we search by class features as well
            if lgpl:
                func_matches_software = get_match_score(
                    main=main, redis=redis, input_path=input_path, features_map=class_features_map,
                    features_type="classes", libraries=lgpl) if class_features_map else None
                for lib_id in lgpl:
                    # sort by cumulative TFIDF if no UNIQ feature is found
                    if lib_id in func_matches_software:
                        if main.rrc:
                            if main.USE_VERSION_DIFFERENCES:
                                logger.critical("input %s complies with LGPL of %s with score %s!", input_path, lib_id, feat_matches_versions[lib_id])
                                main.rrc.handle().hset(input_path, lib_id + '(lgpl-match)', feat_matches_versions[lib_id])
                            else:
                                logger.critical("input %s complies with LGPL of %s with score %s!", input_path, lib_id, feat_matches_software[lib_id])
                                main.rrc.handle().hset(input_path, lib_id + '(lgpl-match)', feat_matches_software[lib_id])
                    else:
                        violation_count += 1
                        if main.rrc:
                            if main.USE_VERSION_DIFFERENCES:
                                logger.critical("input %s is violating LGPL of %s with score %s!", input_path, lib_id, feat_matches_versions[lib_id])
                                main.rrc.handle().hset(input_path, lib_id + '(lgpl)', feat_matches_versions[lib_id])
                            else:
                                logger.critical("input %s is violating LGPL of %s with score %s!", input_path, lib_id, feat_matches_software[lib_id])
                                main.rrc.handle().hset(input_path, lib_id + '(lgpl)', feat_matches_software[lib_id])

        if main.rrc:
            main.rrc.handle().hset(input_path, "repo_matches", len(feat_matches_software))
            main.rrc.handle().hset(input_path, "violation_count", violation_count)


# Helper function for search_items
def get_combined_features_map(search_features, str_features_map=None, class_features_map=None,
                              normclass_features_map=None, centroid_features_map=None):
    final_features_map = {}
    if 'strings' in search_features and str_features_map:
        final_features_map.update(str_features_map)
    if 'classes' in search_features and class_features_map:
        final_features_map.update(class_features_map)
    if 'normclasses' in search_features and normclass_features_map:
        final_features_map.update(normclass_features_map)
    if 'centroids' in search_features and centroid_features_map:
        final_features_map.update(centroid_features_map)
    return final_features_map


###########################################################
# Lookup java classes
###########################################################
def search_classes(main, input_path, input_type):
    start = time.time()
    # global values
    global logger, stats_logger, MIN_MATCHING_SCORE, MIN_LOW_LEVEL_MATCHING_SCORE
    logger = main.logger
    stats_logger = main.stats_logger
    signature_java.logger = main.logger
    signature_java.stats_logger = main.stats_logger
    MIN_MATCHING_SCORE = main.MIN_MATCHING_SCORE['java'] if isinstance(main.MIN_MATCHING_SCORE, dict) else main.MIN_MATCHING_SCORE
    MIN_LOW_LEVEL_MATCHING_SCORE = main.MIN_LOW_LEVEL_MATCHING_SCORE['java'] if isinstance(main.MIN_LOW_LEVEL_MATCHING_SCORE, dict) else main.MIN_LOW_LEVEL_MATCHING_SCORE

    if main.keep_sig and main.java_sig_dir:
        if not os.path.exists(main.java_sig_dir):
            os.makedirs(main.java_sig_dir)
        outdir = main.java_sig_dir
    else:
        outdir = tempfile.mkdtemp(prefix="search_classes-")
    # extract signatures from input_path, search in redis servers
    search_items(main=main, input_path=input_path, input_type=input_type, outdir=outdir)
    # cleanup
    if not main.keep_sig:
        shutil.rmtree(outdir)
    # time logging
    end = time.time()
    if stats_logger:
        stats_logger.info("time elapsed for searching %s: %0.2f seconds" % (input_path, end - start))


###########################################################
# Searcher
###########################################################
def run_searcher(main, argv):
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger
    signature_java.logger = main.logger
    signature_java.stats_logger = main.stats_logger

    # the outer args
    if len(argv) != 2:
        logger.error('expects two args')
        exit(1)
    # if we are just testing this repo
    if argv[0] == 'dump':
        main.TEST_REPO = True
    elif argv[0] == 'verbose':
        main.VERBOSE = True

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

    # check if redis is populated
    dbsize, dbval = main.jrc.dbsize()
    if dbsize == 0:
        logger.error("Nothing is indexed! Exiting.")
        exit(1)

    # The process results are stored in main.rrc if available
    result_db = main.rrc.handle() if main.rrc else None
    skip_scanned = main.ignore_scanned
    input_list = get_input_list(main=main, redis=result_db, redis_pipe=main.rrc.pipeline() if main.rrc else None,
                                input_path=input_path, input_type=input_type, path_as_id=True,
                                skip_scanned=skip_scanned, skip_failure=True)

    print ("There are %d input to be searched" % len(input_list))
    # start searching
    if input_list:

        # register signal handler
        signal = utils.Signal()
        signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

        # track progress
        count = len(input_list)
        logger.info("Matching %d libraries/applications", count)

        # if requested parallelism
        if main.QUEUING and main.QUEUING == 'Celery':
            from celery import group
            from celery_tasks import search_java_worker

            # group jobs
            input_count = len(input_list)
            for index in range(0, input_count, JOB_CHUNK):
                tmp_input_list = input_list[index: min(index + JOB_CHUNK, input_count)]
                if index + JOB_CHUNK > input_count:
                    logger.info("Processing the %d %d input" % (index / JOB_CHUNK + 1, input_count - index))
                else:
                    logger.info("Processing the %d %d input" % (index / JOB_CHUNK + 1, JOB_CHUNK))
                job = group(search_java_worker.s(item, input_type) for item in tmp_input_list)
                result = job.apply_async()
                try:
                    result.get()
                except Exception as e:
                    logger.error("Error signaturing jobs: %s", str(e))

        else:  # non-parallel instance
            pb = utils.Progressbar('Matching libs/apps: ', count)
            pb.start()

            count = 0
            for item in input_list:

                # check for interruption
                if signal.caught():
                    break

                if main.TEST_REPO:
                    pb.msg('Testing {0} '.format(item))
                else:
                    pb.msg('Searching {0} '.format(item))

                # lookup libs/apps
                search_classes(main=main, input_path=item, input_type=input_type)

                # update progressbar
                count += 1
                pb.update(count)

            # all done
            if not signal.caught() and pb:
                pb.finish()

    else:
        logger.error("No lib(s) to search")
