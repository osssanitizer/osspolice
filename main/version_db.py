import math
import os
import sys
import numpy as np
import utils
import re
import time
from ast import literal_eval
from itertools import chain
from common import get_typed_key, get_rtyped_key, get_rkey, get_labeled_typed_key, get_labeled_key, get_unlabeled_key

VERSION_DB_TIMEOUT = 120
VERSION_DB_RETRIES = 3


###########################################################
# Create version database
###########################################################
def build_version_db(main, features, software_details, language, logger=None):
    """
    In the version db, use the same version database for version pinpointing!
    1. use md5 node id generation algorithm at file level when indexing
    2. maintain repo-version to unique features mapping, to help identify versions (done separately)

    0. softwares(cnt) -> record the number of software, softwareversions(cnt) -> record the number of software version
    1. software-XXX -> all the features ever appeared in XXX
    2. softwareunique-XXX -> all the unique features for across all versions, maps feature to versions
    3. softwareversion-XXX -> all versions
    4. softwareversiondetail-XXX-version -> {license: LIC, cve_count: N, cve_1: cpe_1, cve_2: cpe2, ...}
    """
    try:
        redis = get_version_redis(main, language)
        if language == 'java':
            # For the java side, the software_details has keys: software_id, version, license, cve_count, cve2cpe
            assert 'software_id' in software_details
            software_field = 'software_id'
            version_field = 'version'
            license_field = 'license'
            cve_count_field = 'cve_count'
            cve2cpe_field = 'cve2cpe'
        elif language == 'native':
            # For the native side, the software_details has keys: repo_id, repo_name, branch
            # TODO: we still need to set license, cve_count, cve2cpe in software_details!
            assert 'repo_name' in software_details
            software_field = 'repo_name'
            version_field = 'branch'
            license_field = 'license'
            cve_count_field = 'cve_count'
            cve2cpe_field = 'cve2cpe'
        else:
            raise Exception("Unexpected language: %s" % language)

        for field in [software_field, version_field, license_field, cve_count_field, cve2cpe_field]:
            software_details.setdefault(field, None)

        # map software to all the features across versions!
        software_id = get_typed_key(typ='software', key=software_details[software_field])
        if not redis.exists(software_id):
            if language == 'java':
                redis.incrby("softwarescnt", 1)
            elif language == 'native':
                redis.incrby("softwares", 1)

        # record all the versions that has been indexed!
        software_id_for_version = get_typed_key(typ='softwareversion', key=software_details[software_field])
        ret = redis.hsetnx(software_id_for_version, software_details[version_field], 1)
        if ret:
            if language == 'java':
                redis.incrby("softwareversionscnt", 1)
            else:
                redis.incrby("softwareversions", 1)

            # if the version hasn't been inserted before (i.e., the first time we process this version key!)
            # add information about the license and vulnerabilities
            software_id_for_versiondetail = get_labeled_typed_key(label='softwareversiondetail',
                                                                  typ=software_details[software_field],
                                                                  key=software_details[version_field])

            version_details = dict()
            version_details['license'] = software_details[license_field]
            version_details['cve_count'] = software_details[cve_count_field]
            if version_details['cve_count']:
                version_details.update(software_details[cve2cpe_field])
            redis.hmset(software_id_for_versiondetail, version_details)

        # map software version to all the unique features across all versions!
        software_unique_id = get_typed_key(typ='softwareunique', key=software_details[software_field])
        start = time.time()
        for feature, feature_info in features.items():
            # software_id maps to {feature: version_or_version_count} mapping
            set_status = redis.hsetnx(software_id, feature, [software_details[version_field]])
            if set_status:
                if logger:
                    logger.debug("This is unique feature for current version!")
                redis.hset(software_unique_id, feature, software_details[version_field])

            else:
                some_versions = None
                try:
                    some_versions = literal_eval(redis.hget(software_id, feature))
                except Exception as e:
                    if logger:
                        logger.error("failed to get versions for key %s, Error: %s", feature, str(e))

                if not some_versions or len(some_versions) == 0:
                    if logger:
                        logger.error("failed to set version for feature %s: %s! Ignoring!", feature, feature_info)
                    continue
                elif len(some_versions) == 1 and software_details[version_field] in some_versions:
                    if logger:
                        logger.debug("revisiting a recorded unique feature for current version!")
                else:
                    if len(some_versions) == 1:
                        fix_start = time.time()
                        redis.hset(software_id, feature, some_versions + [software_details[version_field]])
                        redis.hdel(software_unique_id, feature)
                        if logger:
                            logger.debug(
                                "removing %s from unique feature set of version %s of software %s took %f seconds",
                                feature, some_versions[0], software_details[software_field], time.time() - fix_start)
                    else:
                        logger.debug(
                            "revisiting a fixed feature, i.e. features for existing versions has been removed!")
        if logger:
            logger.info("setting %d features for version %s of software %s took %f seconds", len(features),
                        software_details[version_field], software_details[software_field], time.time() - start)

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error("[%s, %s, %s] Error building version database for %s: %s",
                     exc_type, fname, exc_tb.tb_lineno, software_id, str(e))


def is_unstable_version(tag):
    tag = tag.lower()
    return any(re.search(term, tag) for term in ['\drc', 'rc\d', 'alpha', 'beta', 'preview', 'unstable'])


def get_version_string(tag, hack=False):
    # normal case: version.1.1
    # openssl: OpenSSL_1_0_1k, OpenSSL_0_9_7k -> "OpenSSL 1.0.2g  1 Mar 2016"
    # libpng: libpng-v1.0.5h -> "libpng version 1.6.10 - March 6, 2014"
    # jpeg-turbo: 1.5.0  -> "libjpeg-turbo 1.5.0"
    # opencv: 2.4.12.2 -> "opencv-2.4.11"
    # openjpeg: 2.0.0 -> "openjpeg"
    # libtiff: Release-v4-0-6 -> "LIBTIFF, Version 3.9.2"
    # box2d: v2.3.0 -> ""
    # libgdx: 1.9.6 -> ""
    # tinyxml2: 4.0.1 -> ""
    #
    # split by _, -, .,
    #
    # failure case: libXXX3-4.3.5
    DELIMITERS = ',|\.|-|_|/|\||\\\\'
    version_parts = re.split(DELIMITERS, tag)
    all_numbers = []
    version_started = False

    # XXX: Hack for OpenSSL
    is_openssl = 'OpenSSL' in tag
    has_fips = 'FIPS' in tag
    for part in version_parts:
        # has digit
        if re.search('\d+', part):
            if not version_started:
                version_started = True
            all_numbers.extend(re.findall('(\d+[a-zA-Z]*)', part))
        else:

            if version_started:
                break
    # verstr = '.'.join(all_numbers)
    # in character matching '-' is a special character, and need to be escaped!
    delimiters = '[.\-_]'
    verstr = delimiters.join(all_numbers)
    # either match the full version string, or start/end with non-version related strings
    verstr_pattern = '(^|v|[^,:.\w])%s($|[^,:.\w])' % verstr
    if hack and is_openssl:
        if has_fips:
            verstr_pattern = 'OpenSSL' + verstr_pattern + 'fips'
        else:
            verstr_pattern = 'OpenSSL' + verstr_pattern
    return verstr_pattern


def is_version_feature(version, feature, ver_is_pattern=False):
    # feature may have spaces, split them
    if len(re.findall('(\d+)', version)) <= 1:
        # there is less than one digit in the version tag!
        return False

    version_pattern = version if ver_is_pattern else get_version_string(version, hack=True)
    if re.search(version_pattern, feature):
        return True
    else:
        return False


def get_hierarchy_redis(main, language, pipeline=False):
    if language == "native":
        hierarchy_redis = main.nrc.pipeline() if pipeline else main.nrc.handle()
    elif language == "java":
        hierarchy_redis = main.jrc.pipeline() if pipeline else main.jrc.handle()
    else:
        raise Exception("unknown search type: %s", language)
    return hierarchy_redis


def get_version_redis(main, language, pipeline=False):
    if language == "native":
        version_redis = main.nvrc.pipeline() if pipeline else main.nvrc.handle()
    elif language == "java":
        version_redis = main.jvrc.pipeline() if pipeline else main.jvrc.handle()
    else:
        raise Exception("unknown search type: %s", language)
    return version_redis


###########################################################
# Search version database
###########################################################
def search_version_db(main, input_path, features, matched_details, feat2plain, language, searchfeat2classes=None,
                      classes2searchfeat=None, logger=None, returnStrings=False):
    """
    1. get all the unique features for a particular software
    2. for each unique feature, check whether they are actually matched, i.e. the class containing that unique feature
      in the OSS and app should match!
    3. find the version that matched maximum number of unique features

    :param main: detector object
    :param input_path: path to the search binary
    :param features: features from the binary
    :param matched_details: matched detail
    :param feat2plain: maps feature id to plain text of features
    :param language: native or java
    :param searchfeat2classes: maps feature id to class ids
    :param classes2searchfeat: maps class id to feature id
    :param logger: logger object
    :param returnStrings: whether to return strings or not
    :return: version match detail
    """
    redis = get_version_redis(main, language)

    matched_version_details = {}
    for software_id, _ in matched_details.items():
        if logger:
            logger.info("matching versions for software %s", software_id)

        # 1. get all unique features
        if logger:
            logger.info("getting all unique features")
        query_software_id_for_version = get_typed_key(typ='softwareversion', key=software_id)
        all_versions = redis.hkeys(query_software_id_for_version)
        if logger:
            logger.info("all versions are (count %d): %s", len(all_versions), all_versions)

        if len(all_versions) <= 1:
            if logger:
                logger.info("software %s has no more than 1 versions, cannot match versions!", software_id)
            matched_version_details.setdefault(software_id, {})
            continue

        features_list = features.keys()
        features_set = set(features)

        software_unique_id = get_typed_key(typ='softwareunique', key=software_id)
        software_unique_size = redis.hlen(software_unique_id)
        # depending on the size of unique features vs. search features, match on redis side or client side
        version2matched_uniq_features = {}
        if len(features_set) > software_unique_size:
            logger.info("search %d > unique %d, fetch all the unique features and compare on the client side!",
                        len(features_set), software_unique_size)
            uniq_features = redis.hgetall(software_unique_id)
            for feature in features_set & set(uniq_features):
                feature_version = uniq_features[feature]
                version2matched_uniq_features.setdefault(feature_version, set())
                version2matched_uniq_features[feature_version].add(feature)
        else:
            logger.info("search %d <= unique %d, query all the search features and compare on the redis side!",
                        len(features_set), software_unique_size)
            redis_pipe = get_version_redis(main, language, pipeline=True)
            for feature in features_list:
                redis_pipe.hget(get_typed_key(typ='softwareunique', key=software_id), feature)
            featversions_list = redis_pipe.execute()
            for feature, feature_version in zip(features_list, featversions_list):
                if not feature_version:
                    continue
                version2matched_uniq_features.setdefault(feature_version, set())
                version2matched_uniq_features[feature_version].add(feature)

        # 2. find the matched unique features
        matched_uniq_features = list(chain(*version2matched_uniq_features.values()))
        if logger:
            logger.info("find the matched unique features from %d potential uniq features", len(matched_uniq_features))

        feat2classids = {}
        redis_hierarchy_pipe = get_hierarchy_redis(main, language, pipeline=True)
        for feat in matched_uniq_features:
            redis_hierarchy_pipe.hkeys(feat)
        classids_lists = redis_hierarchy_pipe.execute()
        classid_list = []
        classid2feature_set = {}
        for feat, class_ids in zip(matched_uniq_features, classids_lists):
            class_ids = [class_id for class_id in class_ids if class_id.startswith(('file-', 'files-'))]
            feat2classids[feat] = class_ids
            for class_id in class_ids:
                if class_id not in classid2feature_set:
                    node_type, _ = class_id.split('-', 1)
                    if node_type == 'files':
                        # java, r-files-XXX -> {strings/functions-XXX: freq, ...}
                        redis_hierarchy_pipe.hkeys(get_rkey(key=class_id))
                    elif node_type == 'file':
                        # native, file_XXX -> {str/func/funcname_XXX: freq, ...}
                        redis_hierarchy_pipe.hkeys(class_id.replace('-', '_'))
                    classid2feature_set.setdefault(class_id, set())
                    classid_list.append(class_id)
        feats_lists = redis_hierarchy_pipe.execute()
        for class_id, feats in zip(classid_list, feats_lists):
            node_type, _ = class_id.split('-')
            if node_type == 'file':
                # native, ignore variables in the class to feats mapping
                feats = [feat.replace('_', '-') for feat in feats if feat.startswith(('str_', 'funcname_', 'func_'))]
            elif node_type == 'files':
                # java, ignore function names in the class to feats mapping
                feats = [feat for feat in feats if feat.startswith(('strings-', 'normclasses-', 'centroids-'))]
            classid2feature_set[class_id].update(feats)
        filtered_matched_uniq_features = filter_matched_features(
            main=main, software=software_id, features_set=features_set, matched_feats=matched_uniq_features,
            feat2files=feat2classids, file2feats=classid2feature_set, feat2plain=feat2plain, search_type=language,
            searchfeat2files=searchfeat2classes, file2searchfeats=classes2searchfeat, logger=logger)

        # 3. find the version that matched maximum number of unique features!
        if logger:
            logger.info("find the version that matched maximum number of unique features!")
        matched_uniq_features = filtered_matched_uniq_features
        if logger:
            logger.info("input path %s matched software %s, and the matched uniq features are: %s",
                        input_path, software_id, matched_uniq_features)
        if main.USE_VERSION_AS_FEATURE:
            # get version strings for feature, skip the features that is already unique for a particular version!
            feat2verstr = {feature: feat2plain[feature] for feature in features_set if
                           feature not in matched_uniq_features}
        versions_score = {}
        for feature_version in all_versions:
            version_matched_feats = version2matched_uniq_features.get(feature_version, set())
            # get the plain text of features
            tag_matched_feats = set()

            # use tag string to match against the strings from binary, and mark matches as version matches.
            feature_version_pattern = get_version_string(feature_version, hack=True)
            if main.USE_VERSION_AS_FEATURE:
                # match version in the features set
                for feat, featplain in feat2verstr.items():
                    # reduce number of calls to get_version_string
                    if is_version_feature(feature_version_pattern, featplain, ver_is_pattern=True):
                        version_matched_feats.add(feat)
                        tag_matched_feats.add(feat)

            if len(version_matched_feats) == 0:
                continue
            if logger:
                logger.info("version %s has %d matched uniq features\n"
                            "features are:\n%s\n"
                            "plaintexts are:\n%s\n",
                            feature_version, len(version_matched_feats), version_matched_feats,
                            [feat2plain[feat] for feat in version_matched_feats if feat in feat2plain])

            for feat in version_matched_feats:
                if feat in feat2plain:
                    log_info = feat2plain[feat]
                else:
                    if logger:
                        logger.error("The matched unique feature %s, must have a reverse plain text mapping", feat)
                is_good_feature = (feat in tag_matched_feats) or is_version_feature(feature_version_pattern, log_info,
                                                                                    ver_is_pattern=True)
                feature_credit = 0
                if is_good_feature:
                    if feat in tag_matched_feats:
                        feature_credit = 41
                        if logger:
                            logger.info("use_tag_feature, detected version %s in search string %s", feature_version,
                                        log_info)
                    else:
                        feature_credit = 100
                        if logger:
                            logger.info("detected version %s in matched string %s", feature_version, log_info)
                if returnStrings:
                    versions_score.setdefault(feature_version, {})
                    versions_score.setdefault(log_info, 0)
                    versions_score[feature_version][log_info] += feature_credit if is_good_feature else 1
                else:
                    versions_score.setdefault(feature_version, 0)
                    versions_score[feature_version] += feature_credit if is_good_feature else 1
        if returnStrings:
            matched_version_details[software_id] = sorted(versions_score.items(), key=lambda k: sum(k[1].values()),
                                                          reverse=True)
        else:
            matched_version_details[software_id] = sorted(versions_score.items(), key=lambda k: k[1], reverse=True)

    # Prepare the version detect result for logging!
    for software_id in matched_details:
        matched_version_details[software_id] = get_distinct_version_info(
            version_matches=matched_version_details[software_id],
            tfidf_matches=matched_details[software_id],
            logger=logger)
    return matched_version_details


def filter_matched_features(main, software, features_set, matched_feats, feat2files, file2feats, feat2plain,
                            search_type, searchfeat2files=None, file2searchfeats=None, logger=None):
    filtered_matched_feats = set()
    redis_pipe = get_hierarchy_redis(main, search_type, pipeline=True)
    feat2refcnt = {}
    feat_set = set()

    # Use feat2files and file2feats to validate detected unique features
    if searchfeat2files and file2searchfeats:
        # Co-location based filtering for Java!
        # Cache the feat2refcnt
        for feat in matched_feats:
            search_files = searchfeat2files[feat]
            index_files = feat2files[feat]
            for search_file in search_files:
                feat_set.update(file2searchfeats[search_file])
            for index_file in index_files:
                feat_set.update(file2feats[index_file])
        feat_list = list(feat_set)
        for feat in feat_list:
            redis_pipe.hget(feat, 'refcnt')
        refcnts = redis_pipe.execute()
        for feat, refcnt in zip(feat_list, refcnts):
            feat2refcnt[feat] = int(refcnt) if refcnt else 0

        # Use the classes structure on the apk side, to compare against the structure on the index side!
        for feat in matched_feats:
            # all the features in version db is labeled, all the features in java/native db is unlabeled!
            feat_matched = False
            search_files = searchfeat2files[feat]
            index_files = feat2files[feat]
            for index_file in index_files:
                index_filefeats = file2feats[index_file]
                for search_file in search_files:
                    search_filefeats = file2searchfeats[search_file]
                    feat_matched = is_matched_feature(
                        main=main, feature=feat2plain[feat], search_filefeats=search_filefeats,
                        index_filefeats=index_filefeats, feat2refcnt=feat2refcnt, logger=logger)
                    if feat_matched:
                        filtered_matched_feats.add(feat)
                        break
                if feat_matched:
                    break

    else:
        # Co-location based filtering for C/C++!
        # Rely on the source code structure, i.e., most features in the source file should present in the binary!
        # Cache the feat2refcnt
        for feat in matched_feats:
            index_files = feat2files[feat]
            for index_file in index_files:
                feat_set.update(file2feats[index_file])
        feat_list = list(feat_set)
        for feat in feat_list:
            redis_pipe.hget(feat, 'refcnt')
        refcnts = redis_pipe.execute()
        for feat, refcnt in zip(feat_list, refcnts):
            feat2refcnt[feat] = int(refcnt) if refcnt else 0

        # Use the index side structure information to filter uniq features!
        for feat in matched_feats:
            if logger:
                logger.debug("checking co-location features for %s (%s)", feat, feat2plain[feat])
            index_files = feat2files[feat]
            for index_file in index_files:
                index_filefeats = file2feats[index_file]
                search_filefeats = index_filefeats & features_set
                if is_matched_feature(main=main, feature=feat2plain[feat], search_filefeats=search_filefeats,
                                      index_filefeats=index_filefeats, feat2refcnt=feat2refcnt, logger=logger):
                    filtered_matched_feats.add(feat)
                    break

    if logger:
        logger.info("filtered %d potential uniq features into %d actual uniq matched features for software %s!",
                    len(matched_feats), len(filtered_matched_feats), software)

    return filtered_matched_feats


###########################################################
# Given a matched software and potential versions, find out the exact version that matched!
###########################################################
def get_idf(main, feature, feat2refcnt=None, norm_idf=True):
    try:
        index_redis = main.jrc.handle()
        if feat2refcnt and "files" not in feat2refcnt:
            feat2refcnt["files"] = int(index_redis.get("files"))
        total_num_parent_like_nodes = feat2refcnt["files"]
        if feat2refcnt and feature not in feat2refcnt:
            feat2refcnt[feature] = int(index_redis.hget(feature, 'refcnt'))
        num_matching_parents = feat2refcnt[feature]
        idf = utils.idf(float(total_num_parent_like_nodes), float(num_matching_parents))
        if norm_idf:
            idf /= utils.idf(float(total_num_parent_like_nodes), 1)
    except:
        # the refcnt is not available!
        idf = 1
    return idf


def is_matched_feature(main, feature, search_filefeats, index_filefeats, dist='tfidf', feat2refcnt=None, logger=None):
    """
    Compare search and index class to see whether they are matching!

    :param main: the detector object
    :param feature: human readable feature
    :param search_filefeats: features in search class
    :param index_filefeats: features in index class
    :param dist: algorithm used to compare, currently support jaccard, tfidf
    :return:
    """
    search_set = set(search_filefeats)
    index_set = set(index_filefeats)
    matched_set = search_set & index_set
    # TODO: Used matched ratio! But there are other options for matched ratio as well!
    if dist == 'jaccard':
        matched_ratio = float(len(matched_set)) / len(search_set | index_set)
    elif dist == 'tfidf':
        # get idf for all the features
        feat2idf = {}
        for tmpfeat in search_set | index_set:
            feat2idf[tmpfeat] = get_idf(main, tmpfeat, feat2refcnt=feat2refcnt)
        numeritor = sum(feat2idf[feat] for feat in search_set & index_set)
        dominator = sum(feat2idf[feat] for feat in search_set | index_set)
        matched_ratio = float(numeritor) / dominator
    else:
        raise Exception("Not implemented yet!")
    if logger:
        logger.debug("feat %s has matched ratio: %f" % (feature, matched_ratio))
        logger.debug("search_features are:\n%s\nindex_features are:\n%s\nmatched_features are:\n%s" %
                     (search_set, index_set, matched_set))
    return matched_ratio > main.MIN_VERSION_PERCENT_MATCH


def get_distinct_version_info(version_matches, tfidf_matches, logger=None):
    # NOTE: it is possible that the version matches identified doesn't belong to tfidf matches!
    if len(version_matches) > 0:
        # tfidf must have versions
        version_dict = {}
        for record in tfidf_matches:
            # version is the very first element!
            version_dict[record[0]] = list(record)
        new_version_matches = []
        for version, score in version_matches:
            if version in version_dict:
                new_version_matches.append(tuple(version_dict[version] + [score]))
            else:
                if logger:
                    logger.error("version %s not from tfidf_matches %s", version, tfidf_matches)
        if len(new_version_matches) == 0:
            # directly return the tfidf based scores
            return get_distinct_version_info(new_version_matches, tfidf_matches)
        else:
            return new_version_matches
    else:
        # add an zero at the end
        return [tuple(list(record) + [0]) for record in tfidf_matches]
