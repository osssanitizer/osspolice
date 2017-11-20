#!/usr/bin/python

import sys
import os
import re
import fnmatch
import math
import time
import common
import utils
from os.path import dirname, join, basename, exists
from ast import literal_eval
from itertools import groupby, izip
from common import skip_set, FileType, leaf_types, internal_types
from process_result import get_repo_groups
from version_db import search_version_db
import subprocess

###########################################################
# init state
###########################################################
logger = None
stats_logger = None
dump_logger = None
common_features = None
DEMANGLER = 'arm-linux-androideabi-c++filt'
MIN_MATCHING_SCORE = None
MIN_LOW_LEVEL_MATCHING_SCORE = None


###########################################################
# Helper functions
###########################################################
# computes the TF-IDF score: product of tf and idf.
def tfidf(main, redis, feature, item, item_freq, num_matching_items, num_total_items=None, norm_term=1.0):
    try:
        if not num_total_items:
            num_total_items = int(redis.get("repos"))

        if isinstance(norm_term, str):
            if not norm_term in ('total', 'unique', 'max_score', 'min_score'):
                raise Exception("invalid norm term %s", norm_term)
            # norm_term can be one of 'total', 'unique', 'max_score', 'min_score'
            norm_term = float(redis.hget(item, norm_term))

        idf_val = utils.idf(num_total_items, num_matching_items)
        logger.debug("feature %s matching item %s total items: %d matching items: %d idf: %0.6f",
                     feature, item, num_total_items, num_matching_items, idf_val)

        tf_val = utils.tf(item_freq, norm_term)
        logger.debug("feature %s matching item: %s item freq: %d norm term %d tf: %0.6f",
                     feature, item, item_freq, norm_term, tf_val)
        return utils.tfidf(tf_val, idf_val)

    except Exception as e:
        logger.error("TFIDF exception for item %s: %s", item, str(e))
        return None


def get_lib_list(arg):
    lib_list = []

    # single lib
    if os.path.isfile(arg) and arg.endswith('.so'):
        lib_path = arg
        lib_name = os.path.basename(arg)
        lib_list.append(lib_name)

    # root lib dir
    elif os.path.isdir(arg):
        for lib_name in os.listdir(arg):
            lib_path = os.path.join(arg, lib_name)
            lib_list.append(lib_name)

    # file containing list of libs
    elif os.path.isfile(arg):
        try:
            import csv, json
            csv_file = open(arg)
            reader = csv.DictReader(csv_file, delimiter=',')
            logger.info("Building library list")

            # register signal handler
            signal = utils.Signal()
            signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

            # parse file containing repo list
            path_name = None
            if 'store_path' in reader.fieldnames:
                path_name = 'store_path'
            elif 'so_path' in reader.fieldnames:
                path_name = 'so_path'
            elif 'filepath' in reader.fieldnames:
                path_name = 'filepath'
            else:
                logger.warn("Failed to find so path column from input file: %s,, considering is as plain file list",
                            arg)

            if path_name:
                for row in reader:
                    lib_list.append(row[path_name])
            else:
                lib_list = filter(bool, open(arg, 'r').read().split('\n'))

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logger.error("[%s, %s, %s] Error parsing lib list file %s: %s",
                         exc_type, fname, exc_tb.tb_lineno, arg, str(e))
            return None

    return lib_list


###########################################################
# STATS
###########################################################

# format
# lib      len=25%       len=50%       len=75%      len=100%      len=125%      len=150%      len=175%
# name | total ascii | total ascii | total ascii | total ascii | total ascii | total ascii | total ascii
def accumulate_stats(main, min_thresh, max_thresh, cstr, total_stats, ascii_stats):
    if max_thresh <= min_thresh or (max_thresh - min_thresh) < 25:
        return

    for i in utils.in_range(min_thresh, max_thresh, 25):
        idx = (i / 25) - 1
        if len(cstr) >= utils.fraction(i, main.MIN_STRING_LEN):
            if idx not in total_stats:
                total_stats[idx] = 1
            else:
                total_stats[idx] += 1
            if utils.is_ascii(cstr):
                if idx not in ascii_stats:
                    ascii_stats[idx] = 1
                else:
                    ascii_stats[idx] += 1


def log_stats(lib_path, min_thresh, max_thresh, total_stats, ascii_stats):
    res = ''
    for i in utils.in_range(min_thresh, max_thresh, 25):
        idx = (i / 25) - 1
        res += str(total_stats[idx]) + ", " + str(ascii_stats[idx]) + ", "
    stats_logger.info("%s, strs, %s", os.path.basename(lib_path), res[:-2])


def demangle(names, parameters):
    try:
        args = [DEMANGLER, '-i']
        if parameters:
            args.append('-p')
        args.extend(names)
        pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout, _ = pipe.communicate()
        demangled = stdout.split("\n")
        # Each line ends with a newline, so the final entry of the split output
        # will always be ''.
        assert len(demangled) == len(names) + 1
        return demangled[:-1]
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error("[%s, %s, %s] failed to demangle C++ names: %s", exc_type, fname, exc_tb.tb_lineno, str(e))
        return []


###########################################################
# String extractor
###########################################################
def get_strings(main, lib_path):
    """
    Function to extract strings from a shared library file.
    """
    if stats_logger:
        max_thresh = 175
        if main.MIN_STRING_LEN <= 4:
            min_thresh = 75
        elif main.MIN_STRING_LEN > 4 and main.MIN_STRING_LEN < 8:
            min_thresh = 50
        else:
            min_thresh = 25
        total_stats = {}
        ascii_stats = {}

    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
        from elftools.common.utils import parse_cstring_from_stream
        from elftools.common.py3compat import (ifilter, byte2int, bytes2str, itervalues, str2bytes)

        with open(lib_path, 'rb') as stream:
            elffile = ELFFile(stream)
            section = elffile.get_section_by_name('.rodata')
            if not section or section['sh_type'] == 'SHT_NOBITS':
                logger.warn("No .rodata section found")
                return None, None

            if section.header['sh_type'] == 'SHT_PROGBITS':
                # build a map of strings and their count
                strings = {}
                count = 0

                # Reference:
                # https://github.com/eliben/pyelftools/blob/master/scripts/readelf.py
                found = False
                data = section.data()
                dataptr = 0

                while dataptr < len(data):
                    while (dataptr < len(data) and
                           not (32 <= byte2int(data[dataptr]) <= 127)):
                        dataptr += 1

                    if dataptr >= len(data):
                        break

                    endptr = dataptr
                    while endptr < len(data) and byte2int(data[endptr]) != 0:
                        endptr += 1

                    found = True
                    logger.debug('  [%6x]  %s' % (dataptr, bytes2str(data[dataptr:endptr])))

                    cstr = bytes2str(data[dataptr:endptr])

                    # string inflation to workaround concatenated multi-line strings generated by parser
                    cstr = cstr[:-1] if cstr.endswith('\n') else cstr
                    cstr_tmp = cstr.replace("\r", "").replace("\n", "\\n")
                    cstr_arr = cstr.replace("\r", "").split("\n")
                    cstr_arr.append(cstr_tmp)  # add extracted string as well

                    # iterate over them
                    for cstr in cstr_arr:
                        logger.debug("Found string %s len: %d min_len: %d min_percent: %s",
                                     cstr, len(cstr), main.MIN_STRING_LEN, main.MIN_PERCENT_MATCH)

                        if not main.TEST_LIB and stats_logger:
                            accumulate_stats(main, min_thresh, max_thresh, cstr, total_stats, ascii_stats)

                        # bookeeping strings
                        if len(cstr) >= main.MIN_STRING_LEN and utils.is_ascii(cstr):
                            logger.debug("the string from binary is: %s", cstr)

                            if is_common_feature(feature=cstr, feature_type='str'):
                                continue
                            if main.TEST_LIB:
                                cstr = 'str-' + cstr
                            strings.setdefault(cstr, 0)
                            strings[cstr] += 1
                            count += 1
                    dataptr = endptr

                if not main.TEST_LIB and stats_logger:
                    # log_stats(lib_path, min_thresh, max_thresh, total_stats, ascii_stats)
                    pass
                if not found:
                    logger.info('No strings found in this section.')
                return count, strings
            else:
                logger.warn("No SHT_PROGBITS section found")
                return None, None

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error("[%s, %s, %s] Error extracting strings: %s", exc_type, fname, exc_tb.tb_lineno, str(e))
        return None


###########################################################
# Dynamic feature extractor (function/variable)
###########################################################
# build a map of dynamic names and their count
def scan_section(main, features, feat_type, lib_path, section):
    """
    Function to extract dynamic names from a shared library file.
    """
    try:
        from elftools.elf.sections import SymbolTableSection

        if not section or not isinstance(section, SymbolTableSection) or section['sh_entsize'] == 0:
            return 0

        logger.info("symbol table '%s' contains %s entries", section.name, section.num_symbols())

        count = 0
        for nsym, symbol in enumerate(section.iter_symbols()):
            # set the type checks
            if feat_type == 'function':
                FEATURE_TYPE = 'STT_FUNC'
            elif feat_type == 'variable':
                FEATURE_TYPE = 'STT_OBJECT'
            else:
                raise Exception("Unexpected feat_type: " + feat_type)

            # check for types and update features
            if symbol['st_info']['type'] == FEATURE_TYPE and symbol['st_shndx'] != 'SHN_UNDEF':
                # bookeeping function/variable names
                func = symbol.name
                if not func in features:
                    features[func] = 1
                else:
                    features[func] += 1
                count += 1

            if not main.TEST_LIB and stats_logger:
                stats_logger.debug("%s, %ss, %s, %s", os.path.basename(lib_path), feat_type, len(features),
                                   len(set(features)))
        return count

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error("[%s, %s, %s] Error extracting %ss: %s", exc_type, fname, exc_tb.tb_lineno, feat_type, str(e))


def get_dynamic_features(main, lib_path, feat_type='function'):
    """
    Function to extract function/variable names from a shared library file.
    """
    from elftools.elf.elffile import ELFFile
    from elftools.common.exceptions import ELFError

    count = 0
    features = {}

    try:
        with open(lib_path, 'rb') as stream:
            elffile = ELFFile(stream)
            count += scan_section(main, features, feat_type, lib_path, elffile.get_section_by_name('.symtab'))
            count += scan_section(main, features, feat_type, lib_path, elffile.get_section_by_name('.dynsym'))
        return count, features
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error("[%s, %s, %s] Error extracting %ss: %s", exc_type, fname, exc_tb.tb_lineno, feat_type, str(e))


###########################################################
# Object extractor
###########################################################
def get_objects(main, lib_path):
    """
    Function to extract global/external objs from a shared library file.
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.common.exceptions import ELFError
        from elftools.elf.sections import SymbolTableSection

        with open(lib_path, 'rb') as stream:
            elffile = ELFFile(stream)
            for section in elffile.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue

                if section['sh_entsize'] == 0:
                    continue

                logger.info("symbol table '%s' contains %s entries", section.name, section.num_symbols())

                for nsym, symbol in enumerate(section.iter_symbols()):
                    if symbol['st_info']['type'] == 'STT_OBJECT' and symbol['st_shndx'] != 'SHN_UNDEF':
                        yield symbol.name

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error("[%s, %s, %s] Error extracting objects: %s", exc_type, fname, exc_tb.tb_lineno, str(e))


def get_featcnt(featcounters, search_features):
    featcnt = 0
    if 'str' in search_features:
        featcnt += featcounters['strcnt']
    if 'var' in search_features:
        featcnt += featcounters['varcnt']
    if 'func' in search_features:
        featcnt += featcounters['funccnt']
    if 'funcname' in search_features:
        featcnt += featcounters['funcnamecnt']
    return featcnt


def get_uniqfeatcnt(featcounters, search_features):
    uniqfeatcnt = 0
    if 'str' in search_features:
        uniqfeatcnt += featcounters['uniqstrcnt']
    if 'var' in search_features:
        uniqfeatcnt += featcounters['uniqvarcnt']
    if 'func' in search_features:
        uniqfeatcnt += featcounters['uniqfunccnt']
    if 'funcname' in search_features:
        uniqfeatcnt += featcounters['uniqfuncnamecnt']
    return uniqfeatcnt


###########################################################
# Lookup by matched items to find unmatched items
###########################################################
def get_unmatches(main, redis, matches, tree, feat2attributes):
    """
    Before calling build_unmatched_tree, we want to finish all the redis queries using pipeline.
    We first get all the children for first-seen parents, then query the featcnt for both the parent
    and first-seen children. The featcnt are computed if not present. This guarantees that featcnt
    is available for every possible parent and child.

    We also maintain the parent to all_children mapping, by querying tree or redis (if parent not present),
    this mapping are used in build_unmatched_tree to iterate for featfreq
    """

    parent_list = []
    redis_pipe = main.nrc.pipeline()

    # get all children for all parent, this is used in build_unmatched_tree for iteration purpose
    logger.debug("get all children for all non-file parent, this is used in build_unmatched_tree for iteration purpose")

    # separate list for all parents despite their availabilty in the tree{}
    parent2all_children = {}

    for parent, children in matches.items():
        parent_type, parent_id = parent.split('-', 1)
        if parent_type != "repo" and parent_type != "branch":
            if parent not in tree:
                # get all children
                parent2all_children.setdefault(parent, [])
                tree.setdefault(parent, {})
                tree[parent]['featcnt'] = 0
                parent_list.append(parent)
                redis_pipe.hgetall(parent.replace('-', '_'))
            else:
                parent2all_children[parent] = get_children_from_tree(parent, tree)
    members_list = redis_pipe.execute()

    # separate list querying refcnt/license for all children
    refcnt_query_feature_list = []

    # parent is definitely not in tree, because they were already filtered in the previous loop
    # get feature frequency for all child to parent mappings!
    logger.debug("get feature frequency for unknown mappings, including parent and children")
    for parent, members in izip(parent_list, members_list):
        if parent not in feat2attributes:
            feat2attributes.setdefault(parent, {})  # avoid duplicate redis queries
            refcnt_query_feature_list.append(parent)
            if main.USE_GROUPED_MATCH:
                # license are going to be used in grouped match, filename is not used yet!
                redis_pipe.hmget(parent, ['refcnt', 'license', 'filetype'])
            else:
                redis_pipe.hget(parent, 'refcnt')
        else:
            if 'refcnt' in feat2attributes[parent]:
                tree[parent]['refcnt'] = feat2attributes[parent]['refcnt']
            if 'license' in feat2attributes[parent]:
                tree[parent]['license'] = feat2attributes[parent]['license']
            if 'filetype' in feat2attributes[parent]:
                tree[parent]['filetype'] = feat2attributes[parent]['filetype']

        # XXX optimization: prefetch all members' featcnt
        for r_member, member_featcounters in members.items():

            member = r_member.replace('_', '-')
            parent2all_children[parent].append(member)

            if member == parent:
                continue

            # TODO: single list for refcnt, featcnt
            # members may be in the tree, or may have been queried
            member_type, _ = member.split('-', 1)
            if member_type in leaf_types:
                # optimization: cache featfreq/featcnt for leaf nodes here!
                member_featcnt = int(member_featcounters)
                member_uniqfeatcnt = 1
                if not member in matches[parent]:
                    # negative featfreq = featcnt for unmatched feature
                    tree[parent][member] = -1 if main.USE_UNIQ_FEATURES_FOR_TF else -member_featcnt
                else:
                    # positive featfreq = featcnt for matched feature
                    tree[parent][member] = 1 if main.USE_UNIQ_FEATURES_FOR_TF else member_featcnt
            elif member_type in internal_types:
                member_featcounters = literal_eval(member_featcounters)
                member_featcnt = get_featcnt(member_featcounters, main.search_features)
                member_uniqfeatcnt = get_uniqfeatcnt(member_featcounters, main.search_features)
            else:
                logger.error("unexpected type of member %s", member_type)

            # optimization: do not query redis, get featcnt for parent by adding children featcnt
            tree[parent]['featcnt'] += member_uniqfeatcnt if main.USE_UNIQ_FEATURES_FOR_TF else member_featcnt

            # build list to prefetch refcnt for all members
            if member not in feat2attributes:
                feat2attributes.setdefault(member, {})  # avoid duplicate redis queries
                refcnt_query_feature_list.append(member)
                if main.USE_GROUPED_MATCH:
                    # license are going to be used in grouped match
                    redis_pipe.hmget(member, ['refcnt', 'license', 'filetype'])
                else:
                    redis_pipe.hget(member, 'refcnt')

            # cache 'featcnt'
            if member not in tree:
                tree.setdefault(member, {})
                tree[member]['featcnt'] = member_uniqfeatcnt if main.USE_UNIQ_FEATURES_FOR_TF else member_featcnt
                if 'refcnt' in feat2attributes[member]:
                    tree[member]['refcnt'] = feat2attributes[member]['refcnt']
                if 'license' in feat2attributes[member]:
                    tree[member]['license'] = feat2attributes[member]['license']
                if 'filetype' in feat2attributes[member]:
                    tree[member]['filetype'] = feat2attributes[member]['filetype']

    # fill in refcnt for unknown items
    logger.info("fill in refcnt for unknown items")
    refcnt_list = redis_pipe.execute()
    for feature, refcnt_or_tuple in izip(refcnt_query_feature_list, refcnt_list):
        # any feature that is not in tree or feat2attributes has been resolved!
        if main.USE_GROUPED_MATCH:
            tmprefcnt, tmplicense, tmpfiletype = refcnt_or_tuple
            tree[feature]['refcnt'] = feat2attributes[feature]['refcnt'] = int(tmprefcnt) if tmprefcnt else 0
            if tmplicense:
                # license can be used to get rid of frequent files/folders!
                tree[feature]['license'] = feat2attributes[feature]['license'] = tmplicense
            if tmpfiletype:
                # filetype is only set for files, dir wont have this attribute!
                tree[feature]['filetype'] = feat2attributes[feature]['filetype'] = tmpfiletype
        else:
            tree[feature]['refcnt'] = feat2attributes[feature]['refcnt'] = int(
                refcnt_or_tuple) if refcnt_or_tuple else 0

    # iterate over matching nodes looking them up to find unmatched ones
    logger.info("iterate over matching nodes looking them up to find unmatched ones")
    for parent, children in matches.items():
        parent_type, parent_id = parent.split('-', 1)
        if parent_type != "repo" and parent_type != "branch":
            build_unmatched_tree(main, redis, parent, children, parent2all_children[parent], tree)


def build_unmatched_tree(main, redis, parent, known_children, all_children, tree):
    parent_type, parent_id = parent.split('-', 1)
    parent_id = long(parent_id)

    # From each child, we walk up.
    # The featcnt for each parent must already be available here, so we need to walk from the child to parents
    # to update their feature frequency.
    #
    # 1. all the parents and their children are mapped to featcnt now!
    # 2. parent to children relationship is cached in all_children!
    # 3. the parent shows up meaning that the featfreq has changed, so we re-compute
    # if parent_type == "file":
    logger.debug("parent %s has %d known and %d unknown children total %d",
                 parent, len(known_children), len(all_children) - len(known_children), len(all_children))

    # reset parent featfreq
    tree[parent]['featfreq'] = 0

    for child in all_children:

        child_type, child_id = child.split('-', 1)
        if child_type in leaf_types:
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


def get_children_from_tree(parent, tree):
    return [child for child in tree[parent].keys() if '-' in child]


def get_child_idf(main, redis, child, parent_type, tree, norm_idf=True):
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
        parents_type = parent_type + 's'
        if parents_type not in tree:
            tree[parents_type] = int(redis.get(parents_type))
        total_num_parent_like_nodes = tree[parents_type]
        if not total_num_parent_like_nodes:
            raise Exception("failed to get parent like nodes")
        idf = utils.idf(float(total_num_parent_like_nodes), float(num_matching_parents))
        if norm_idf:
            idf /= utils.idf(float(total_num_parent_like_nodes), 1)
        return idf
    except Exception as e:
        logger.error("Failed to calculate idf for child %s parent type %s: %s",
                     child, parent_type, str(e))
        return None


def filter_matches(main, redis, matches, tree, node2group, level):
    # fix the refcnt in tree based on SEARCH_SIMHASH_DISTANCE
    utils.fix_refcnt(main=main, feat2refcnt=tree, node2group=node2group, matches=matches, level=level, logger=logger)

    next_matches = {}
    for parent, children in matches.items():

        parent_type, parent_id = parent.split('-', 1)
        if parent_type == "repo" or parent_type == "branch":
            logger.error("invalid parent %s. ignoring!", parent)
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
        #       parent -> {child1: featfreq, child2: featfreq, ..., featcnt, featfreq}
        #       child1 -> {grandchild1: featfreq, grandchild2: featfreq, ..., featcnt, featfreq}
        # parent -> children, and child -> featcnt, featfreq, are used to compute the tfidf
        #
        # all child keys has a '-' in, they are 'dir-, file-, str-, func-' etc.
        children_to_check = get_children_from_tree(parent, tree)

        # prepare the values to use in grouped match
        if main.USE_GROUPED_MATCH:

            # prepare the matched str freq and func freq at matched file/dir level!
            if parent_type in internal_types:
                children_grouped_strfreq = 0
                children_grouped_varfreq = 0
                children_grouped_funcfreq = 0
                children_grouped_funcnamefreq = 0
                if parent_type == 'file':
                    for child in children_to_check:
                        if tree[parent][child] > 0:
                            child_type, _ = child.split('-')
                            if child_type == 'str':
                                children_grouped_strfreq += tree[parent][child]
                            elif child_type == 'var':
                                children_grouped_varfreq += tree[parent][child]
                            elif child_type == 'func':
                                children_grouped_funcfreq += tree[parent][child]
                            elif child_type == 'funcname':
                                children_grouped_funcnamefreq += tree[parent][child]
                            else:
                                logger.error("file %s has unexpected child type %s", parent, child)
                elif parent_type == 'dir':
                    for child in children_to_check:
                        if 'grouped_strfreq' in tree[child]:
                            children_grouped_strfreq += tree[child]['grouped_strfreq']
                        if 'grouped_varfreq' in tree[child]:
                            children_grouped_varfreq += tree[child]['grouped_varfreq']
                        if 'grouped_funcfreq' in tree[child]:
                            children_grouped_funcfreq += tree[child]['grouped_funcfreq']
                        if 'grouped_funcnamefreq' in tree[child]:
                            children_grouped_funcnamefreq += tree[child]['grouped_funcnamefreq']

                tree[parent]['grouped_strfreq'] = children_grouped_strfreq
                tree[parent]['grouped_varfreq'] = children_grouped_varfreq
                tree[parent]['grouped_funcfreq'] = children_grouped_funcfreq
                tree[parent]['grouped_funcnamefreq'] = children_grouped_funcnamefreq

            # grouped matches (featfreq, featcnt) works only when child is at file/dir level,
            # i.e., when parent is at dir level!
            if parent_type == 'dir':
                children_grouped_featcnt = 0
                children_grouped_featfreq = 0
                for child in children_to_check:
                    if 'grouped_featcnt' in tree[child] and 'grouped_featfreq' in tree[child]:
                        children_grouped_featcnt += tree[child]['grouped_featcnt']
                        children_grouped_featfreq += tree[child]['grouped_featfreq']
                    else:
                        # str/var/func -> file, no grouped_featfreq/featcnt
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
                if child_type in leaf_types:
                    logger.error("Unexpected! feature freq is zero for a feature %s. Ignoring!", child_type)
                    continue
                else:
                    # expected number of features
                    # child_feature_freq = -float(tree[child]['featcnt'])
                    logger.debug("In the new score system, we don't subtract")

            # default grouped feat count/freq to actual value
            child_grouped_feature_count = child_feature_count
            child_grouped_feature_freq = child_feature_freq
            if main.USE_GROUPED_MATCH and parent_type == 'dir':
                # if the matching ratio is low
                if child_type in internal_types:
                    # strfreq and funcfreq and funcnamefreq
                    child_grouped_strfreq = tree[child]['grouped_strfreq'] if 'grouped_strfreq' in tree[child] else 0
                    child_grouped_varfreq = tree[child]['grouped_varfreq'] if 'grouped_varfreq' in tree[child] else 0
                    child_grouped_funcfreq = tree[child]['grouped_funcfreq'] if 'grouped_funcfreq' in tree[child] else 0
                    child_grouped_funcnamefreq = tree[child]['grouped_funcnamefreq'] if 'grouped_funcnamefreq' in tree[
                        child] else 0

                    # featcnt and featfreq
                    if 'grouped_featcnt' in tree[child] and 'grouped_featfreq' in tree[child]:
                        child_grouped_feature_count = tree[child]['grouped_featcnt']
                        child_grouped_feature_freq = tree[child]['grouped_featfreq']

                    child_match_ratio = float(
                        child_grouped_feature_freq) / child_grouped_feature_count if child_grouped_feature_count else 0

                    # Rule 1: if the child is a source file (not header), and has no function matches, then exclude it
                    # all file should have filetype!
                    if (child_type == 'file' and 'filetype' in tree[child]
                            and tree[child]['filetype'] in [FileType.C, FileType.CPP]
                            and child_grouped_funcfreq + child_grouped_funcnamefreq < main.MIN_GROUPED_FUNCFREQ):
                        tree[parent]['grouped_featcnt'] -= child_grouped_feature_count
                        tree[parent]['grouped_featfreq'] -= child_feature_freq
                        tree[parent]['grouped_strfreq'] -= child_grouped_strfreq
                        tree[parent]['grouped_varfreq'] -= child_grouped_varfreq
                        tree[parent]['grouped_funcfreq'] -= child_grouped_funcfreq
                        tree[parent]['grouped_funcnamefreq'] -= child_grouped_funcnamefreq
                        logger.debug("skipped child %s when matching parent %s due to low matching ratio: %s",
                                     child, parent, child_match_ratio)
                        continue

                    # Rule 2: if the child has license file
                    if child_type == 'dir' and 'license' in tree[child] and tree[child]['license']:
                        # NOTE: this child directly is a separate library, and we should exclude it when computing
                        # group_featcnt, and subtract the featfreq contributed from this child
                        # (there should be no such count, because we already excluded them in the get_matches phase
                        tree[parent]['grouped_featcnt'] -= child_grouped_feature_count
                        tree[parent]['grouped_featfreq'] -= child_feature_freq
                        tree[parent]['grouped_strfreq'] -= child_grouped_strfreq
                        tree[parent]['grouped_varfreq'] -= child_grouped_varfreq
                        tree[parent]['grouped_funcfreq'] -= child_grouped_funcfreq
                        tree[parent]['grouped_funcnamefreq'] -= child_grouped_funcnamefreq
                        logger.debug(
                            "skipped child %s when matching parent %s due to presence of license file in dir: %s",
                            child, parent, tree[child]['license'])
                        continue

                    # Rule 3: if the child has much higher refcnt than the rest of the child
                    if child_type in main.GROUPED_NODE_TYPES and len(children_to_check) >= 2:
                        # for each child, compare it with all other child in the same folder
                        import numpy as np
                        # TODO: should we consider the unmatched other children or all the other children?!
                        # [tree[other_child]['refcnt'] for other_child in children_to_check if other_child != child
                        # and tree[other_child]['featfreq'] <= 0]
                        other_children_avg_refcnt = np.mean(
                            [tree[other_child]['refcnt'] for other_child in children_to_check if other_child != child])
                        if tree[child]['refcnt'] >= other_children_avg_refcnt * main.MAX_GROUPED_REFCNT_RATIO:
                            # NOTE: the child is too frequent, so we consider it as third party dir and exclude it
                            tree[parent]['grouped_featcnt'] -= child_grouped_feature_count
                            tree[parent]['grouped_featfreq'] -= child_feature_freq
                            tree[parent]['grouped_strfreq'] -= child_grouped_strfreq
                            tree[parent]['grouped_varfreq'] -= child_grouped_varfreq
                            tree[parent]['grouped_funcfreq'] -= child_grouped_funcfreq
                            tree[parent]['grouped_funcnamefreq'] -= child_grouped_funcnamefreq
                            logger.debug(
                                "skipped child %s when matching parent %s due to high refcnt: %s (avg of others %s)",
                                child, parent, tree[child]['refcnt'], other_children_avg_refcnt)
                            continue

                    # Rule 4: if the child has a low match ratio (use GROUPED_NODE_TYPES to control the types of nodes to apply this filtering)
                    if child_type in main.GROUPED_NODE_TYPES and child_match_ratio <= main.MIN_GROUPED_PERCENT_MATCH:
                        # NOTE: using MIN_GROUPED_PERCENT_MATCH because examples/tests may have some matching ratio
                        # update the group_featcnt to reflect that this child is not supposed to match!
                        # we also need to subtract the featfreq contributed from this child
                        tree[parent]['grouped_featcnt'] -= child_grouped_feature_count
                        tree[parent]['grouped_featfreq'] -= child_feature_freq
                        tree[parent]['grouped_strfreq'] -= child_grouped_strfreq
                        tree[parent]['grouped_varfreq'] -= child_grouped_varfreq
                        tree[parent]['grouped_funcfreq'] -= child_grouped_funcfreq
                        tree[parent]['grouped_funcnamefreq'] -= child_grouped_funcnamefreq
                        logger.debug("skipped child %s when matching parent %s due to low matching ratio: %s",
                                     child, parent, child_match_ratio)
                        continue

            # use tfidf metric to derive feature weight
            if not parent_feature_count:
                child_idf = None
                child_score = 0
                child_expected = 0
            else:
                child_idf = get_child_idf(main, redis, child, parent_type, tree)
                if main.USE_GROUPED_MATCH and parent_type == 'dir':
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
            logger.debug("parent id %s type %s score %f normscore %f",
                         parent_id, parent_type, parent_score, parent_normscore)
            if main.USE_GROUPED_MATCH and parent_type == 'dir':
                next_matches[parent] = (long(tree[parent]['grouped_featfreq']), long(tree[parent]['grouped_featcnt']),
                                        parent_score, parent_normscore)
            else:
                next_matches[parent] = (long(tree[parent]['featfreq']), long(tree[parent]['featcnt']),
                                        parent_score, parent_normscore)

    return next_matches


#####################################################################
# Lookup by features and aggregate matching items
# Time Complexity : O(Number of features * Number of matching items)
#####################################################################
def get_matches(main, redis, lib_path, repo_matches, features, feat2attributes, matched_set, level, tree=None):
    num_matched_features = 0
    matches = {}  # maps matched parent to all child features

    # only used when level == 0
    item_list = []

    # get matches and set of items
    logger.info("get matches and set of items")
    feature_list = features.keys()

    redis_pipe = main.nrc.pipeline()
    for feature in feature_list:
        redis_pipe.hgetall(feature)
    feature_items_list = redis_pipe.execute()

    # iterate over features to looking them up to find matching items
    logger.info("finished querying %s features for matched items", len(feature_list))
    for feature, matched_items in izip(feature_list, feature_items_list):

        feature_freq, feature_count, feature_score, feature_normscore = features[feature]
        if not matched_items:
            continue

        num_matched_features += feature_freq
        logger.debug("feature %s matched items: %s", feature, matched_items)

        # skip popular feature
        if 'refcnt' in matched_items and int(matched_items['refcnt']) > main.MAX_PER_STR_MATCHING_REPO_COUNT:
            continue

        feature_type, _ = feature.split('-', 1)
        # iterate over all matching items, ranking them by their matching scores
        feat2attributes.setdefault(feature, {})
        for item, item_value in matched_items.items():
            if item == 'refcnt':
                feat2attributes[feature]['refcnt'] = int(item_value)
            if item == 'license':
                feat2attributes[feature]['license'] = item_value
            if item == 'filetype':
                feat2attributes[feature]['filetype'] = item_value
            if item == 'filename':
                feat2attributes[feature]['filename'] = item_value

            # skip if not needed or same as parent
            if item in skip_set or item == feature:
                continue

            item_type, _ = item.split('-', 1)
            if item_type == 'repo' or item_type == 'branch':

                if feature_count < main.MIN_MATCHING_REPO_FEATURE_COUNT:
                    logger.info("filtered repo %s due to low leaf feature count %s", item, feature_count)
                    continue

                if main.USE_GROUPED_MATCH:
                    if (tree and tree[feature]['grouped_funcfreq'] + tree[feature][
                            'grouped_funcnamefreq'] < main.MIN_GROUPED_FUNCFREQ):
                        logger.info("filtered repo %s due to low function matches %d!", item,
                                    tree[feature]['grouped_funcfreq'] + tree[feature]['grouped_funcnamefreq'])
                        continue
                    else:
                        logger.info("repo %s matched %d functions %d function names %d variables and %d strings!",
                                    item, tree[feature]['grouped_funcfreq'], tree[feature]['grouped_funcnamefreq'],
                                    tree[feature]['grouped_varfreq'], tree[feature]['grouped_strfreq'])

                if feature_normscore < MIN_MATCHING_SCORE:
                    logger.info("filtered repo %s due to low matching score %s", item, feature_normscore)
                    continue

                logger.info("input %s matched repo %s from feature %s with score %s and normscore %f",
                            lib_path, item, feature, feature_score, feature_normscore)
                # update repo matches
                if main.USE_GROUPED_MATCH:
                    repo_matches[item] = (feature_freq, feature_count, feature_score, feature_normscore,
                                          tree[feature]['grouped_strfreq'], tree[feature]['grouped_varfreq'],
                                          tree[feature]['grouped_funcfreq'], tree[feature]['grouped_funcnamefreq'])
                else:
                    repo_matches[item] = (feature_freq, feature_count, feature_score, feature_normscore)
                # record the mapping from feature to repo
                tree.setdefault(item, {})
                tree[item][feature] = feature_freq
                continue

            else:
                # update parent to children mapping, as matches
                if level == 0 and item not in matches:
                    # redis_pipe.hget(item, 'featcnt')
                    redis_pipe.hlen(item.replace('-', '_'))
                    item_list.append(item)

                # check if the match comes from a licensed directory, if yes, ignore the matching item
                if main.USE_GROUPED_MATCH and feature_type == 'dir' and 'license' in feat2attributes[feature]:
                    logger.debug(
                        "filtered dir %s from dir feature %s because the child has license file with license %s",
                        item, feature, feat2attributes[feature]['license'])
                    continue

                # update matches
                matches.setdefault(item, set())
                matches[item].add(feature)

    matched_set.update(matches.keys())

    ############################################################
    # filter the matched files, if the matched number ratio of children is smaller than a certain amount
    ############################################################
    if level == 0:
        item_featcnt_list = redis_pipe.execute()
        item2featcnt = {}
        for item, item_featcnt in izip(item_list, item_featcnt_list):
            # Map item to item_uniq_cnt
            item2featcnt[item] = int(item_featcnt) if item_featcnt else 0

        old_matches_count = len(matches)
        min_pct = main.MIN_PERCENT_MATCH['native'] if isinstance(main.MIN_PERCENT_MATCH, dict) else main.MIN_PERCENT_MATCH
        matches = {item: matched_children for item, matched_children in matches.items()
                   if item2featcnt[item] > 0 and float(len(matched_children) * 100) / item2featcnt[item] >= min_pct}
        new_matches_count = len(matches)
        logger.info("filtered %d file matches into %d file matches using ratio filtering", old_matches_count,
                    new_matches_count)

    logger.info("finished computing matches")
    return num_matched_features, matches


###########################################################
# Library filter
###########################################################
def skip_lib(main, lib_path):
    logger.debug("Checking lib %s", lib_path)
    try:
        if not os.path.isfile(lib_path):
            logger.error("skipping %s: not a file", lib_path)
            return True

        elif not os.path.exists(lib_path):
            logger.error("skipping %s: doesn't exist", lib_path)
            return True

        elif main.ignore_scanned and main.rrc and main.rrc.handle().exists(lib_path):
            logger.error("Skipping processed lib_path %s", lib_path)
            return True

        try:
            import magic
            lib_info = magic.from_file(lib_path).split(',')
            lib_type = lib_info[0]
            if lib_type != "ELF 32-bit LSB shared object" and "ELF 32-bit" not in lib_type:
                logger.error("skipping %s: not a ELF 32-bit shared object", lib_path)
                return True
            lib_arch = lib_info[1]
            if lib_arch != " ARM":
                logger.error("skipping %s: not an ARM exectable", lib_path)
                return True

            return False

        except ImportError as ie:
            logger.error("skipping %s: %s", lib_path, str(ie))
            return True

        except magic.MagicException as me:
            logger.error("skipping %s: magic exception %s", lib_path, str(me))
            return True

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error("[%s, %s, %s] skipping %s: %s", exc_type, fname, exc_tb.tb_lineno, lib_path, str(e))
        return True


###########################################################
# Lookup items by features
###########################################################
def search_items(main, redis, lib_path, features, features2plain=None):
    # tree: maps node id to
    #       {'featcnt': xxx, 'featfreq': xxx, 'child1': xxxfreq, 'child2': xxxfreq,
    #        'grouped_featcnt': xxx, 'grouped_featfreq': xxx,
    #        'grouped_funcfreq': xxx, 'grouped_strfreq': xxx, 'grouped_funcnamefreq': xxx, 'grouped_varfreq': xxx,
    #        'refcnt': xxx, 'filetype': xxx, 'license': xxx, 'filename': xxx}, also has key files, dirs, repos
    # matches: maps parent id, to all matched children ids
    # repo_matches: maps repo id to feature score
    # feat2refcnt: maps redis key to refcnt value, this is used to reduce queries to redis
    # matches_set: record the items that have been matched before, to avoid reconsidering, (this is a temporary bug
    # fix to the infinite loop problem)
    raw_features = features
    tree = {}
    repo_matches = {}
    # includes three attributes: refcnt, filetype, license, used to cache the fields
    feat2attributes = {}
    matched_set = set()
    node2group = {}

    logger.info("start get_matches for %s", lib_path)
    time_point = time.time()
    level = 0
    # XXX hack: the level is a mandatory temporary hack to fix the infinite loop problem. the node changed
    # attribute doesn't seem to work here.
    while features and level < 1000:

        # Phase 1: lookup features
        try:
            num_matched_features, matches = get_matches(main=main, redis=redis, lib_path=lib_path,
                                                        repo_matches=repo_matches, features=features,
                                                        feat2attributes=feat2attributes, matched_set=matched_set,
                                                        level=level, tree=tree)
        except Exception as e:
            logger.error("Error computing matches from features at level %d, error %s", level, str(e))
            return None

        if stats_logger:
            new_time_point = time.time()
            stats_logger.info("time elapsed for finding %d matches from %d features at level %d: %s seconds",
                              len(matches), len(features), level, new_time_point - time_point)
            time_point = new_time_point

        logger.info("num features: %d num matched features: %d, num matched parents %d",
                    len(features), num_matched_features, len(matches))
        if len(matches) == 0:
            break

        # Phase 2: build unmatched tree
        try:
            get_unmatches(main=main, redis=redis, matches=matches, tree=tree, feat2attributes=feat2attributes)
        except Exception as e:
            logger.error("Error computing unmatches from matches at level %d, error %s", level, str(e))
            return None

        if stats_logger:
            new_time_point = time.time()
            stats_logger.info("time elapsed for computing unmatched features for %d parents at level %d: %s seconds",
                              len(matches), level, new_time_point - time_point)
            time_point = new_time_point

        # Phase 3: filter matches
        try:
            features = filter_matches(main=main, redis=redis, matches=matches, tree=tree, node2group=node2group,
                                      level=level)
        except Exception as e:
            logger.error("Error filter matches from matches: %s, error %s", matches, str(e))
            return None

        if stats_logger:
            new_time_point = time.time()
            stats_logger.info(
                "time elapsed for filtering features for %d matches in to %d features at level %d: %s seconds",
                len(matches), len(features), level, new_time_point - time_point)
            time_point = new_time_point

        # next round
        logger.debug("next features: %s", features)
        level += 1

    # we have a list of matches
    if len(repo_matches):
        # aggregate repo matches by name
        repo_name_matches = {}
        for repo, score_tuple in repo_matches.items():
            match_type, repo_id = repo.split('-', 1)
            if match_type == 'branch':
                # fix the branch matching
                branch = repo
                # branch is also mapped to licenses!
                try:
                    target_repo = None
                    target_license = None
                    for key, value in redis.hgetall(branch).items():
                        if key.startswith('repo-'):
                            target_repo = key
                        elif key == 'license':
                            target_license = value
                    repo = target_repo
                    _, repo_id = repo.split('-', 1)
                except:
                    logger.error("Error getting the repo id for branch: %s, Ignoring!", branch)
                    continue
            else:
                branch = None
            if len(score_tuple) == 4:
                featfreq, featcnt, score, normscore = score_tuple
                strfreq, varfreq, funcfreq, funcnamefreq = -1, -1, -1, -1
            elif len(score_tuple) == 8:
                featfreq, featcnt, score, normscore, strfreq, varfreq, funcfreq, funcnamefreq = score_tuple
            else:
                logger.error("unknown size %d of score_tuple: %s", len(score_tuple), score_tuple)
            query_result = main.ndb.query("full_name", gh_id=repo_id)
            version_str = branch.split('-', 2)[-1]
            try:
                # update the full name to match detail mapping
                full_name = str(query_result[0][0][0])
                repo_name_matches.setdefault(full_name, [])
                repo_name_matches[full_name].append((version_str, branch, target_license, featfreq, featcnt, score,
                                                     normscore, strfreq, varfreq, funcfreq, funcnamefreq))
                # update the branch to repo mapping
                tree.setdefault(repo, {})
                tree[repo][branch] = featfreq
            except Exception as e:
                logger.error("Error fetch full name for repo %s branch %s: %s", repo, branch, str(e))
                repo_name_matches.setdefault(repo, [])
                repo_name_matches[repo].append((version_str, branch, target_license, featfreq, featcnt, score,
                                                normscore, strfreq, varfreq, funcfreq, funcnamefreq))

        if stats_logger:
            new_time_point = time.time()
            stats_logger.info("time elapsed for querying software information for repos: %s seconds",
                              new_time_point - time_point)
            time_point = new_time_point

        # in decreasing order of matching score
        repo_name_matches = {lib_id: sorted(versions, key=lambda x: x[5], reverse=True) for lib_id, versions in
                             repo_name_matches.items()}
        if main.USE_VERSION_DIFFERENCES:
            # repo_name_matches: maps full_name -> version matching details!
            repo_version_matches = search_version_db(main=main, input_path=lib_path, features=raw_features,
                                                     matched_details=repo_name_matches, feat2plain=features2plain,
                                                     language="native", logger=logger)
            logger.critical("TFIDF based ranking of versions are:\n%s", repo_name_matches)
            logger.critical("UNIQ FEATURE based ranking of versions are:\n%s", repo_version_matches)

        # group the matched result based on the set of matched features
        if main.USE_GROUPED_RESULT:
            # grouped_repo_name_matches: maps full_name -> group id
            repo_groups, repo2matched_leaves, repo2matched_tree = get_repo_groups(
                main=main, repo_matches=repo_name_matches, tree=tree, result_type="native", logger=logger)

            # print the set of matched features for each repo
            if main.VERBOSE:
                for repo_name in repo_name_matches:
                    logger.info("repo %s matched features:\n%s", repo_name,
                                sorted({feat: features2plain[feat] for feat in repo2matched_leaves[repo_name]}.items(),
                                       key=lambda k: k[0]))
                    logger.info("repo %s matched tree:\n%s", repo_name, repo2matched_tree[repo_name])

            # store the repo groups info
            logger.info("repo groups are %s", repo_groups)
            main.rrc.handle().hset(lib_path, 'repo_groups', repo_groups)
            main.rrc.handle().hset(lib_path, 'repo_group_count', len(set(repo_groups.values())))

        # limit the number of version per repo to write back, because they can be a lot, pick 5
        MAX_VERSION_COUNT = 5
        if main.USE_VERSION_DIFFERENCES:
            for lib_id, versions in repo_version_matches.items():
                # the versions are already sorted in version_db.py
                if len(versions) > MAX_VERSION_COUNT:
                    versions = versions[:MAX_VERSION_COUNT]
                    repo_version_matches[lib_id] = versions
            logger.critical("lib %s matched repos: %s", lib_path,
                            sorted(repo_version_matches.items(), key=lambda k: (k[1][0][-1], k[1][0][5]), reverse=True))
        else:
            for lib_id, versions in repo_name_matches.items():
                if len(versions) > MAX_VERSION_COUNT:
                    versions = versions[:MAX_VERSION_COUNT]
                    repo_name_matches[lib_id] = versions
            logger.critical("lib %s matched repos: %s", lib_path,
                            sorted(repo_name_matches.items(), key=lambda k: k[1][0][5], reverse=True))

        for repo in repo_name_matches:
            if main.rrc:
                if main.USE_VERSION_DIFFERENCES:
                    main.rrc.handle().hset(lib_path, repo, repo_version_matches[repo])
                else:
                    main.rrc.handle().hset(lib_path, repo, repo_name_matches[repo])
        if main.rrc:
            main.rrc.handle().hset(lib_path, 'repo_matches', len(repo_name_matches))
    else:
        logger.info("lib %s didn't match", lib_path)
        if main.rrc:
            main.rrc.handle().hset(lib_path, 'repo_matches', 0)
    if stats_logger:
        new_time_point = time.time()
        stats_logger.info("time elapsed for setting results into result db: %s seconds", new_time_point - time_point)
        time_point = new_time_point


###########################################################
# Filter out common features, to avoid pinpointing compiler-related OSS
###########################################################
def load_common_features(main):
    global common_features
    common_features = {}
    if main.common_feature_file:
        if not exists(main.common_feature_file):
            logger.error("common feature file doesn't exist! %s", main.common_feature_file)
        else:
            import csv
            reader = csv.DictReader(open(main.common_feature_file, 'r'))
            type_field = utils.any_and_return(test_fields=['type', 'typ', 'feat_type', 'feature_type'],
                                              target_fields=reader.fieldnames)
            feature_field = utils.any_and_return(test_fields=['feature', 'feat'], target_fields=reader.fieldnames)
            for row in reader:
                common_features.setdefault(row[type_field], set())
                common_features[row[type_field]].add(row[feature_field])
    return common_features


def is_common_feature(feature, feature_type):
    if not common_features:
        return False
    elif feature_type not in common_features:
        return False
    else:
        return feature in common_features[feature_type]


def filter_common_features(features, common_features, feature_type):
    if feature_type not in common_features:
        return features
    if type(features) == dict:
        new_features = {}
        for feature in features:
            if feature not in common_features[feature_type]:
                new_features[feature] = features[feature]
    else:
        new_features = []
        for feature in features:
            if feature not in common_features[feature_type]:
                new_features.append(feature)
    return new_features


###########################################################
# replacement functions
###########################################################
def replace_scope_in_params(s):
    if s.group() == "std::":
        return s.group()
    else:
        return ''


###########################################################
# Lookup library
###########################################################
def search_library(main, lib_path):
    global logger, stats_logger, dump_logger, MIN_MATCHING_SCORE, MIN_LOW_LEVEL_MATCHING_SCORE
    logger = main.logger
    stats_logger = main.stats_logger
    redis = main.nrc.handle()
    MIN_MATCHING_SCORE = main.MIN_MATCHING_SCORE['native'] if isinstance(main.MIN_MATCHING_SCORE, dict) else main.MIN_MATCHING_SCORE
    MIN_LOW_LEVEL_MATCHING_SCORE = main.MIN_LOW_LEVEL_MATCHING_SCORE['native'] if isinstance(main.MIN_LOW_LEVEL_MATCHING_SCORE, dict) else main.MIN_LOW_LEVEL_MATCHING_SCORE

    if skip_lib(main, lib_path):
        if main.rrc and not main.rrc.handle().exists(lib_path):
            # Mark skipped non-processed so files!
            main.rrc.handle().hset(lib_path, 'repo_matches', -1)
        return

    if main.TEST_LIB:
        try:
            if not main.STATS and main.ignore_scanned:
                expected_dump_path = join(main.RESULT_DIR, 'search_dump_%s.csv' % basename(lib_path))
                if exists(expected_dump_path):
                    logger.info("the dump for lib %s has already been generated, Ignoring!", lib_path)
                    return 0

            import logger as applogger
            path = main.RESULT_DIR
            if main.MODE == 'Celery':
                if not main.STATS:
                    path = join(path, 'search')
                else:
                    path = join(path, 'search_worker')
            else:
                path = join(path, 'search')
            if main.STATS:
                path += '_stats_' + str(os.getpid()) + '_' + \
                        utils.ts_now_str(fmt='%Y_%m_%d_%H_%M_%S') + '.csv'
                if main.MODE == 'Celery':
                    dump_logger = applogger.Logger("Dump", path).get()
                else:
                    dump_logger = applogger.Logger("Dump" + lib_path, path).get()
            else:
                path += '_dump_' + os.path.basename(lib_path) + '.csv'
                dump_logger = applogger.Logger("Dump" + lib_path, path).get()

        except Exception as e:
            logger.error(str(e))
            return 0

        logger.info("Testing lib %s", lib_path)

    else:
        logger.info("Searching lib %s", lib_path)
        # time logging
        start = time.time()

    # load common features
    load_common_features(main)

    # build unique string list
    count, str_map = get_strings(main, lib_path)
    if not count:
        logger.warn("no strings found in lib %s", lib_path)
        str_map = {}

    # build unique variable list
    var_map = {}
    count, raw_var_map = get_dynamic_features(main=main, lib_path=lib_path, feat_type='variable')
    if not count:
        logger.warn(" no variables found in lib %s. ignoring!", lib_path)
        raw_var_map = {}
    else:
        for chunk in utils.chunks(raw_var_map.keys(), 50):
            for var_name in demangle(chunk, parameters=False):

                # skip "std" variables
                if var_name.startswith("std::"):
                    logger.debug("skipping std variable %s", var_name)
                    continue

                if main.TEST_LIB:
                    if var_name:
                        var_name += 'var-' + var_name

                if var_name and not is_common_feature(feature=var_name, feature_type='var'):
                    var_map.setdefault(var_name, 0)
                    var_map[var_name] += 1

    # build unique function list
    func_map = {}
    funcname_map = {}
    count, raw_func_map = get_dynamic_features(main=main, lib_path=lib_path, feat_type='function')
    if not count:
        logger.warn("no functions found in lib %s. ignoring!", lib_path)
        raw_func_map = {}
    else:
        for chunk in utils.chunks(raw_func_map.keys(), 50):
            demangled = dict(zip(demangle(chunk, parameters=False), demangle(chunk, parameters=True)))
            for func_params, func_name in demangled.items():

                # skip "std" functions
                if func_name.startswith("std::"):
                    # or func_name.startswith("_WLocale_") or func_name.startswith("_Locale"):
                    logger.debug("skipping std function %s", func_name)
                    continue
                # print func_params, func_name
                pos = func_params.find(func_name)
                if pos == -1:
                    logger.error("failed to find matching func %s in func_params: %s",
                                 func_name, func_params)
                    continue

                # check if this function has parameters
                params = begin = end = None
                if len(func_params) == len(func_name):
                    params = None
                else:
                    params = func_params[len(func_name):]

                func_without_params = None
                if params:
                    params = re.sub(r'\w+::', replace_scope_in_params, params)
                    if '::' in func_name:
                        func_without_params = func_name.rsplit('::', 1)[1]
                    else:
                        func_without_params = func_name
                    func_with_params = func_name + params
                else:
                    if func_name.count('::'):
                        logger.error("function %s contains no parameters but a ::", func_name)
                        continue
                    func_without_params = func_name
                    func_with_params = func_name

                if main.TEST_LIB:
                    if func_with_params:
                        func_with_params = 'func-' + func_with_params
                    if func_without_params:
                        func_without_params = 'funcname-' + func_without_params

                if func_with_params and not is_common_feature(feature=func_with_params, feature_type='func'):
                    func_map.setdefault(func_with_params, 0)
                    func_map[func_with_params] += 1

                if func_without_params and not is_common_feature(feature=func_without_params, feature_type='funcname'):
                    funcname_map.setdefault(func_without_params, 0)
                    funcname_map[func_without_params] += 1

    logger.critical("num strings %d, num funcs %d, num funcnames %d, total %d",
                    len(str_map), len(func_map), len(funcname_map), len(str_map) + len(func_map) + len(funcname_map))

    # nothing here
    if not len(str_map) and not len(raw_var_map) and not len(raw_func_map):
        return None

    # if requested to only dump features
    if main.TEST_LIB:
        try:
            import csv
            dump = str_map
            dump.update(var_map)
            dump.update(func_map)
            dump.update(funcname_map)
            path = dump_logger.handlers[1].baseFilename
            logger.info('dumping data in file: %s', path)
            if main.STATS:
                fieldnames = ['strs', 'vars', 'funcs', 'funcnames', 'total']
                writer = csv.DictWriter(open(path, 'w'), fieldnames=fieldnames)
                writer.writeheader()
                writer.writerow({'strs': len(str_map), 'vars': len(var_map), 'funcs': len(func_map),
                                 'funcnames': len(funcname_map), 'total': len(dump)})
            else:
                fieldnames = ['type', 'freq', 'feature', 'feature_key']
                writer = csv.DictWriter(open(path, 'w'), fieldnames=fieldnames)
                writer.writeheader()
                for k, v in sorted(dump.items(), key=lambda x: x[1], reverse=True):
                    t, k = k.split('-', 1)
                    writer.writerow({'type': t, 'freq': v, 'feature': k,
                                     'feature_key': '%s-%s' % (t, str(utils.get_key(main, k)))})
            return True
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logger.error("[%s, %s, %s] Error dumping features for lib %s: %s",
                         exc_type, fname, exc_tb.tb_lineno, lib_path, str(e))
            return None

    else:
        if stats_logger:
            stats_logger.info("time elapsed for preparing feature list: %s seconds", time.time() - start)

        # build feature map
        features = {}
        features2plain = {}  # used for printing verbose messages!
        for feature in str_map.keys():
            feature_key = "str-" + str(utils.get_key(main, feature))
            if 'str' in main.search_features:
                features[feature_key] = (1, 1, None, None)
            features2plain.setdefault(feature_key, feature)
        for feature in var_map.keys():
            feature_key = "var-" + str(utils.get_key(main, feature))
            if 'var' in main.search_features:
                features[feature_key] = (1, 1, None, None)
            features2plain.setdefault(feature_key, feature)
        for feature in func_map.keys():
            feature_key = "func-" + str(utils.get_key(main, feature))
            if 'func' in main.search_features:
                features[feature_key] = (1, 1, None, None)
            features2plain.setdefault(feature_key, feature)
        for feature in funcname_map.keys():
            feature_key = "funcname-" + str(utils.get_key(main, feature))
            if 'funcname' in main.search_features:
                features[feature_key] = (1, 1, None, None)
            features2plain.setdefault(feature_key, feature)
        logger.debug("features2plain: %s", features2plain)

        # start search
        if len(features):
            search_items(main=main, redis=redis, lib_path=lib_path, features=features, features2plain=features2plain)

        # time logging
        end = time.time()
        if stats_logger:
            stats_logger.info("total time elapsed for searching %s: %0.2f seconds", lib_path, end - start)


###########################################################
# Searcher
###########################################################
def run(main, argv):
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger

    if len(argv) != 2:
        logger.error('expects two args')
        exit(1)

    # if we are just testing this repo
    if argv[0] == 'dump':
        main.TEST_LIB = True
    elif argv[0] == 'stats':
        main.STATS = True
        main.TEST_LIB = True
    elif argv[0] == 'verbose':
        main.VERBOSE = True

    if main.TEST_LIB and not stats_logger:
        logger.error("Enable STATS Logger in config to dump features!")
        exit(1)

    # check if path exists
    if not os.path.exists(argv[1]):
        logger.error('%s does not exist', argv[1])
        exit(1)

    # check toolchain
    if not utils.which(DEMANGLER):
        ndk_root = os.getenv('NDK_TOOLCHAIN')
        if not ndk_root:
            logger.error("%s tool not found and NDK_TOOLCHAIN env var is not set", DEMANGLER)
            exit(1)
        else:
            path = os.path.join(ndk_root, "bin")
            if not os.path.exists(path):
                logger.error("failed to find %s: %s does not exists", DEMANGLER, path)
                exit(1)
            elif os.path.isdir(path):
                PATH = os.getenv('PATH')
                PATH = PATH + ":" + path
                os.environ['PATH'] = PATH
            else:
                logger.error("failed to find %s in %s", DEMANGLER, path)
                exit(1)

    # check if redis is populated
    dbsize, dbval = main.nrc.dbsize()
    if not main.TEST_LIB and dbsize < 10:
        logger.error("Nothing is indexed! Exiting.")
        exit(1)

    global redis
    redis = main.nrc.handle()

    # single lib
    if os.path.isfile(argv[1]) and argv[1].endswith('.so'):

        root_lib_path = os.path.dirname(argv[1])
        lib_list = get_lib_list(argv[1])

    # root lib dir
    elif os.path.isdir(argv[1]):

        root_lib_path = argv[1]
        lib_list = get_lib_list(argv[1])

    # file containing list of libs
    elif os.path.isfile(argv[1]):

        root_lib_path = None
        lib_list = get_lib_list(argv[1])

    else:
        logger.error("invalid option")
        return

    count = 0

    # start searching
    if lib_list:

        # skip
        logger.info("There are %d libs to search", len(lib_list))
        if main.ignore_scanned and main.rrc:
            rrc_pipe = main.rrc.pipeline()
            tmplib_list = []
            for lib_path in lib_list:
                try:
                    _ = unicode(lib_path)
                    rrc_pipe.exists(lib_path)
                    tmplib_list.append(lib_path)
                except:
                    logger.error("lib_path is not a good str for redis %s", lib_path)
            new_lib_list = []
            for lib_path, scanned in zip(tmplib_list, rrc_pipe.execute()):
                if not scanned:
                    new_lib_list.append(lib_path)
            lib_list = new_lib_list
            logger.info("Filtered libs to search to %d", len(lib_list))

        if main.SHUFFLE_INPUT:
            import random
            random.shuffle(lib_list)

        # config
        logger.info("Min string len: %d", main.MIN_STRING_LEN)

        # register signal handler
        signal = utils.Signal()
        signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

        # track progress
        count = len(lib_list)
        if main.TEST_LIB:
            logger.info("Testing %d libraries", count)
            pb = utils.Progressbar('Testing libs: ', count)
        else:
            logger.info("Matching %d libraries", count)
            pb = utils.Progressbar('Matching libs: ', count)
        pb.start()

        # if we are testing
        test = None
        if main.STATS:
            test = 'stats'
        elif main.TEST_LIB:
            test = 'dump'

        # if requested parallelism
        if main.QUEUING and main.QUEUING == 'Celery':
            from celery import group
            from celery_tasks import native_search_worker

            # group jobs
            if root_lib_path:
                job = group(
                    native_search_worker.s(os.path.join(root_lib_path, lib_name), test) for lib_name in lib_list)
            else:
                job = group(native_search_worker.s(lib_path, test) for lib_path in lib_list)
            result = job.apply_async()

            # track worker progress
            completed = 0
            while result.waiting():
                time.sleep(5)
                completed += result.completed_count()
                if completed < count:
                    pb.update(completed)

            # all done
            pb.finish()
            result.get()

        else:  # non-parallel instance

            # search loop
            count = 0
            for item in lib_list:

                # check for interruption
                if signal.caught():
                    break

                if root_lib_path:
                    lib_name = item
                    lib_path = os.path.join(root_lib_path, lib_name)
                else:
                    lib_path = item
                    lib_name = os.path.basename(lib_path)

                if main.TEST_LIB:
                    pb.msg('Testing {0} '.format(lib_name))
                else:
                    pb.msg('Searching {0} '.format(lib_name))

                # lookup lib
                search_library(main, lib_path)

                # update progressbar
                count += 1
                pb.update(count)

            # all done
            if not signal.caught() and pb:
                pb.finish()

    else:
        logger.error("No lib(s) to search")
