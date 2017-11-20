#!/usr/bin/env python

import os
import sys
import re
import csv
import redisclient
import config as appconfig
import logger as applogger
import operator
import json
import time
from itertools import izip
from ast import literal_eval as make_tuple

try:
    # encoding=utf8
    reload(sys)
    sys.setdefaultencoding('utf8')
except:
    pass


###########################################################
# Usage
###########################################################
def print_usage(argv):
    print ('usage: ./%s <kind> <key|job>, where job can be dump_unique or summary or apk_summary or fixtemp'
           ' or monitor_indexing or sampling or dump_comps, dump_popfeats, dump_result_csv, '
           'if job is fixtemp, then we need three more parameters, name, key, value\n'
           'if job is summary, and result is kind, there can be two more parameter summary_file key_pattern' % argv[0])


def smart_get(redis, key, key_type):
    if key_type == "list":
        return redis.lrange(key, 0, -1)
    elif key_type == "hash":
        return sorted(redis.hgetall(key).items(), key=operator.itemgetter(1), reverse=True)
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


def dump_unique(redis_vrc, summaryfile='./software_version_unique_summary.json', detailfile=None):
    # get all software-* keys, for unique strings
    # get all softwareversion-* keys, for versions
    # maintain the version to unique string set mapping
    redis_handle = redis_vrc.handle()
    redis_pipe = redis_vrc.pipeline()

    # fill in software2versions
    software2versions = {}
    software2versioncount = {}
    all_software_version_keys = redis_handle.keys("softwareversion-*")
    for svk in all_software_version_keys:
        redis_pipe.hkeys(svk)
    all_software_versions = redis_pipe.execute()
    for svk, versions in zip(all_software_version_keys, all_software_versions):
        software_id = svk.split('-', 1)[-1]
        software2versions.setdefault(software_id, {})
        software2versioncount.setdefault(software_id, {})
        for version in versions:
            software2versions[software_id].setdefault(version, {})
            software2versioncount[software_id].setdefault(version, 0)

    # we maintain a common global list, and a unique global list
    for software_id in software2versions:
        software_unique_key = 'softwareunique-' + software_id
        unique_feats = redis_handle.hgetall(software_unique_key)
        for feat, version in unique_feats.items():
            software2versions[software_id][version][feat] = 1
            software2versioncount[software_id][version] += 1

    # output to file
    if summaryfile:
        print ("dumping software stats to file %s" % summaryfile)
        json.dump(software2versioncount, open(summaryfile, 'w'), indent=2)
    if detailfile:
        print ("dumping software detail to file %s" % detailfile)
        json.dump(software2versions, open(detailfile, 'w'), indent=2)


def handle_repo_groups(so_path_detail_list):
    # referencing: droidpolice/detector/process_result.py
    repo2groups = {}
    for so_path, repo_groups_str, repo_group_count, repo_matches in so_path_detail_list:
        tmp_repo_groups = make_tuple(repo_groups_str)
        tmp_id2groups = {}
        for repo_name, group_id in tmp_repo_groups.items():
            tmp_id2groups.setdefault(group_id, set())
            tmp_id2groups[group_id].add(repo_name)
            repo2groups.setdefault(repo_name, set())
        for _, groups in tmp_id2groups.items():
            all_groups = set(groups)
            # merge the groups from different repo names
            for group_repo in groups:
                all_groups.update(repo2groups[group_repo])
            # assign the merged group to each repo in the group
            for group_repo in all_groups:
                repo2groups[group_repo].update(all_groups)
    repo2groupids = {}
    group_id = 0
    for repo, group in repo2groups.items():
        if repo not in repo2groupids:
            for rg in group:
                repo2groupids[rg] = group_id
            group_id += 1
    group_count = group_id + 1
    return repo2groupids, group_count


def summarize_apk(redis_rrc, oss_outfile='./oss.json', apk_outfile='./apk.json', lib_outfile='./lib.json',
                  so2apkfile=None):
    redis_handle = redis_rrc.handle()
    # all_keys = redis_handle.keys("*abc*")
    all_keys = redis_handle.keys()
    redis_pipe = redis_rrc.pipeline()
    for key in all_keys:
        redis_pipe.hget(key, 'repo_matches')
    all_matches_count = redis_pipe.execute()
    matched_keys = []
    for key, matches_count in izip(all_keys, all_matches_count):
        if matches_count is None:
            redis_handle.delete(key)
            continue
        matches_count = int(matches_count)
        if matches_count > 0:
            matched_keys.append(key)
            redis_pipe.hgetall(key)

    # the matched paths
    all_matches_detail = redis_pipe.execute()
    print ("all matches detail ready!")
    skip_set = {'repo_matches', 'package_name', 'app_path', 'app_count', 'decision', 'status', 'comment',
                'violation_count', 'repo_groups', 'repo_group_count'}

    # maps software to number of apps matching it
    # key: software
    # value_dict:
    #   value_key: lib path with score or counter name (app count, so count, dex count)
    #   value_value: matching apps or counter value (app count, so count, dex count)
    software_based_summary = {}
    apk_based_summary = {}
    software2app_set = {}
    myindex = 0
    print ("processing the matched results")
    for key, results in izip(matched_keys, all_matches_detail):
        apk_based_summary[key] = results
        for info, score in results.items():
            if info in skip_set:
                if info == 'decision':
                    decision = score
                elif info == "status":
                    status = score
                elif info == "comment":
                    comment = score
                elif info == 'violation_count':
                    violation_count = int(score)
                elif info == 'repo_matches':
                    repo_matches = int(score)
                else:
                    # skip label based key values
                    pass
                continue

            # In java side, it is software_id -> version matched info
            # In native side, it is software_id -> version matched info
            try:
                #######################################################################
                # if this succeeds, it is native
                #######################################################################
                top_results = []
                software_name = info
                max_version_count = -1
                tuple_list = make_tuple(score)
                result_count = 0
                partial_or_full = "full"
                only_gpl = True
                lgpl = False
                # TODO: in the latest verion, there should be one more element uniqscore
                for version, repo_or_version, license, featfreq, featcnt, score, normscore, strfreq, varfreq, funcfreq, funcnamefreq, uniqscore in sorted(
                        tuple_list, key=lambda tup: (tup[-1], tup[5]), reverse=True):

                    # filter some data out, otherwise it is too much data to show!
                    # if (featfreq > 1000 and normscore > 0.6) or (featfreq > 100 and normscore > 0.8):
                    if True:
                        top_results.append(
                            {'version': version, 'featfreq': featfreq, 'featcnt': featcnt, 'score': score,
                             'normscore': normscore, 'uniqscore': uniqscore,
                             'strfreq': strfreq, 'varfreq': varfreq, 'funcfreq': funcfreq, 'funcnamefreq': funcnamefreq,
                             'license': license})
                        # license is a string lists representations.
                        try:
                            license = make_tuple(license)
                        except Exception as e:
                            print ("cannot load license string %s: %s" % (license, str(e)))
                            license = None
                        if not license:
                            only_gpl = False
                        else:
                            for lic in license:
                                if ('gpl' not in lic.lower() and 'see' not in lic.lower()
                                        and 'unclassified' not in lic.lower()):
                                    only_gpl = False
                                if 'lgpl' in lic.lower():
                                    lgpl = True
                        result_count += 1
                        if result_count >= max_version_count > 0:
                            break

                if len(top_results) == 0:
                    continue

                repo_id = repo_or_version
                if only_gpl:
                    if lgpl:
                        software_name = '%s(lgpl)' % software_name
                    else:
                        software_name = '%s(gpl)' % software_name
                else:
                    software_name = '%s(nongpl)' % software_name

            except ValueError:
                # this is java
                top_results = []
                software_name = info
                partial_or_full = "full"
                max_version_count = -1
                tuple_list = make_tuple(score)
                result_count = 0
                for version, repo_id, featfreq, featcnt, score, normscore, uniqscore in sorted(
                        tuple_list, key=lambda tup: (tup[-1], tup[-3]), reverse=True):
                    license = re.search('\(([^\)]*)\)', software_name).groups()[0]
                    top_results.append({'version': version, 'featfreq': featfreq, 'featcnt': featcnt, 'score': score,
                                        'normscore': normscore, 'uniqscore': uniqscore, 'license': license})
                    result_count += 1
                    if max_version_count > 0 and result_count >= max_version_count:
                        break

            path = os.path.basename(key)
            data_row = {'path': key, 'myindex': myindex, 'repo_id': repo_id,
                        'software_name': software_name, "version": version, "is_partial": partial_or_full,
                        'featfreq': featfreq, 'featcnt': featcnt, 'score': score, 'normscore': normscore,
                        'license': license,
                        'top_results': top_results}
            myindex += 1

            software_name = software_name
            software2app_set.setdefault(software_name, set())
            software2app_set[software_name].add(data_row['path'])

            if software_name not in software_based_summary:
                software_based_summary.setdefault(software_name, {})

            if key not in software_based_summary[software_name]:
                software_based_summary[software_name].setdefault(key, {})
                software_based_summary[software_name][key]['version'] = data_row['top_results'][0]['version']
                software_based_summary[software_name][key]['score'] = data_row['top_results'][0]['score']
                software_based_summary[software_name][key]['normscore'] = data_row['top_results'][0]['normscore']

                if 'uniqscore' in data_row['top_results'][0]:
                    software_based_summary[software_name][key]['uniqscore'] = data_row['top_results'][0]['uniqscore']
                if 'strfreq' in data_row['top_results'][0]:
                    software_based_summary[software_name][key]['strfreq'] = data_row['top_results'][0]['strfreq']
                    software_based_summary[software_name][key]['varfreq'] = data_row['top_results'][0]['varfreq']
                    software_based_summary[software_name][key]['funcfreq'] = data_row['top_results'][0]['funcfreq']
                    software_based_summary[software_name][key]['funcnamefreq'] = data_row['top_results'][0][
                        'funcnamefreq']

                software_based_summary[software_name][key]['featcnt'] = data_row['top_results'][0]['featcnt']
                software_based_summary[software_name][key]['featfreq'] = data_row['top_results'][0]['featfreq']
                software_based_summary[software_name][key]['top_results'] = data_row['top_results']
                software_based_summary[software_name]['app_count'] = len(software2app_set[software_name])

    if oss_outfile:
        print ("dumping software based matched result to file %s" % oss_outfile)
        json.dump(software_based_summary, open(oss_outfile, 'w'), indent=2)

    if apk_outfile:
        if so2apkfile:
            print ("dumping lib based matched result to file %s" % lib_outfile)
            json.dump(apk_based_summary, open(lib_outfile, 'w'), indent=2)
            real_apk_based_summary = {}
            so2apk_dict = json.load(open(so2apkfile, 'r'))
            for so_path in apk_based_summary:
                if so_path not in so2apk_dict:
                    continue
                apk_paths = so2apk_dict[so_path]
                for apk_path in apk_paths:
                    real_apk_based_summary.setdefault(apk_path, {})
                    real_apk_based_summary[apk_path].update({k: v for k, v in apk_based_summary[so_path].items()
                                                             if k not in {'repo_groups', 'repo_matches',
                                                                          'repo_group_count'}})
                    real_apk_based_summary[apk_path].setdefault('so_path', [])
                    real_apk_based_summary[apk_path]['so_path'].append(
                        (so_path, apk_based_summary[so_path]['repo_groups'],
                         apk_based_summary[so_path]['repo_group_count'],
                         apk_based_summary[so_path]['repo_matches']))
            # update the repo groups mapping
            for apk_path in real_apk_based_summary:
                repo_groups, repo_group_count = handle_repo_groups(
                    so_path_detail_list=real_apk_based_summary[apk_path]['so_path'])
                real_apk_based_summary[apk_path]['repo_groups'] = repo_groups
                real_apk_based_summary[apk_path]['repo_group_count'] = repo_group_count
                real_apk_based_summary[apk_path]['repo_matches'] = len(repo_groups)
            apk_based_summary = real_apk_based_summary
        print ("dumping apk based matched result to file %s" % apk_outfile)
        json.dump(apk_based_summary, open(apk_outfile, 'w'), indent=2)


def summarize_result(redis_rrc, logger=None, match=None, min_score=None, min_featfreq=None, min_featcnt=None,
                     outfile='./software_based_summary.json', whitelist_file='./whitelist', extract_summary_file=None):
    # extract_summary_file='/data/gpl_violation/data/playdrone-extract_summary_new.pb'):
    """
    Summarize the detected result based on software ids.

    :param redis_rrc: the redis client obj
    :param logger: logger
    :param min_score: min score in summary
    :param min_featfreq: min featfreq
    :param min_featcnt: min featcnt
    :param outfile: the output file
    :param whitelist_file: the whitelist of so names, dex names, and software names, to skip
    :param extract_summary_file: the file to store extraction summary
    :return:
    """
    # 1. aggregate the *Java* violation type by GPL, LGPL!
    #    for each type, output software id, violation score, violation path
    # 2. all the violations in *Native* are GPL now!
    #    print software id, violating digests and scores
    redis_handle = redis_rrc.handle()
    all_keys = redis_handle.keys() if not match else redis_handle.keys(pattern=match)
    redis_pipe = redis_rrc.pipeline()
    for key in all_keys:
        redis_pipe.hget(key, 'repo_matches')
    all_matches_count = redis_pipe.execute()
    matched_keys = []
    for key, matches_count in izip(all_keys, all_matches_count):
        if matches_count is None:
            redis_handle.delete(key)
            continue
        matches_count = int(matches_count)
        if matches_count > 0:
            matched_keys.append(key)
            redis_pipe.hgetall(key)

    # the matched paths
    all_matches_detail = redis_pipe.execute()
    print ("all matches detail ready!")
    skip_set = set(['repo_matches', 'package_name', 'app_path', 'app_count', 'decision', 'status', 'comment'])

    # maps software to number of dex/so files matching it, and number of apps matching it
    # key: software
    # value_dict:
    #   value_key: lib path with score or counter name (app count, so count, dex count)
    #   value_value: matching apps or counter value (app count, so count, dex count)
    software_based_summary = {}
    software2app_set = {}

    # preload extract summary dict, i.e. mapping from components to apps, for generating software based summary
    if extract_summary_file and os.path.exists(extract_summary_file):
        print ("loading extract summary from %s" % extract_summary_file)
        sys.path.append("../viewer/")
        from repo_detail_pb2 import ExtractResult
        from job_util import read_proto_from_file
        er = ExtractResult()
        read_proto_from_file(er, extract_summary_file, binary=True)
        extract_summary = {}
        for componentToApps in er.extract_components:
            extract_summary[componentToApps.component.component_digest] = componentToApps
    else:
        extract_summary = {}

    # TODO: we may use the decision, status, comment column to reduce false positives in display
    whitelist_set = set(
        filter(bool, open(whitelist_file, 'r').read().split('\n'))) if whitelist_file and os.path.exists(
        whitelist_file) else set()

    myindex = 0
    print ("processing the matched results")
    for key, results in izip(matched_keys, all_matches_detail):
        for info, score in results.items():
            decision = '';
            status = '';
            comment = ''
            if info in skip_set:
                if info == 'decision':
                    decision = score
                elif info == "status":
                    status = score
                elif info == "comment":
                    comment = score
                else:
                    # skip label based key values
                    pass
                continue

            # In java side, it is software_id -> version matched info
            # In native side, it is software matched info -> score
            try:
                # if this succeeds, it is native
                top_results = []
                software_name = info
                max_version_count = 3
                result_count = 0
                tuple_list = make_tuple(score)
                for version, repo_id, partial_or_full, featfreq, featcnt, score, normscore in sorted(tuple_list,
                                                                                                     key=lambda tup:
                                                                                                     tup[-2],
                                                                                                     reverse=True):
                    top_results.append({'version': version, 'featfreq': featfreq, 'featcnt': featcnt, 'score': score,
                                        'normscore': normscore})
                    result_count += 1
                    if result_count >= max_version_count:
                        break

            except ValueError:
                # this is java
                top_results = []
                software_name = info
                partial_or_full = "full"
                max_version_count = 3
                tuple_list = make_tuple(score)
                result_count = 0
                for version, repo_id, featfreq, featcnt, score, normscore in sorted(tuple_list, key=lambda tup: tup[-2],
                                                                                    reverse=True):
                    top_results.append({'version': version, 'featfreq': featfreq, 'featcnt': featcnt, 'score': score,
                                        'normscore': normscore})
                    result_count += 1
                    if result_count >= max_version_count:
                        break

            except Exception as e:
                if logger:
                    logger.error("Unexpected key value pair (%s, %s) in name %s", info, score, key)

            path = os.path.basename(key)
            md5hash = path.split('-')[0]
            libname = path.split('-')[-1]

            # package_name, app_path, app_count is stored separately in a protocol buffer file
            if md5hash in extract_summary:
                package_name = [app.package_name for app in extract_summary[md5hash].apps]
                app_path = [app.downloaded_path for app in extract_summary[md5hash].apps]
                app_count = len(extract_summary[md5hash].apps)
            else:
                package_name = [];
                app_path = [];
                app_count = 0

            data_row = {'name': libname, 'md5': md5hash, 'path': key, 'myindex': myindex, 'repo_id': repo_id,
                        'software_name': software_name, "version": version, "is_partial": partial_or_full,
                        'featfreq': featfreq, 'featcnt': featcnt, 'score': score, 'normscore': normscore,
                        'package_name': package_name, 'app_path': app_path, 'app_count': app_count,
                        'decision': decision, 'status': status, 'comment': comment, 'top_results': top_results}
            myindex += 1

            # Update software2app_set and software_based_summary
            if ((min_featfreq and featfreq < min_featfreq) or (min_featcnt and featcnt < min_featcnt) or
                    (min_score and score < min_score) or software_name in whitelist_set or libname in whitelist_set):
                continue

            software_name = software_name
            software2app_set.setdefault(software_name, set())
            software2app_set[software_name].update(data_row['app_path'])

            if software_name not in software_based_summary:
                software_based_summary.setdefault(software_name, {})
                software_based_summary[software_name]['app_count'] = 0
                software_based_summary[software_name]['so_count'] = 0
                software_based_summary[software_name]['dex_count'] = 0
                software_based_summary[software_name]['apk_count'] = 0

            if key not in software_based_summary[software_name]:
                software_based_summary[software_name].setdefault(key, {})
                software_based_summary[software_name][key].setdefault('package_name', [])
                software_based_summary[software_name][key].setdefault('app_path', [])
                software_based_summary[software_name][key]['version'] = data_row['top_results'][0]['version']
                software_based_summary[software_name][key]['score'] = data_row['top_results'][0]['score']
                software_based_summary[software_name][key]['normscore'] = data_row['top_results'][0]['normscore']
                software_based_summary[software_name][key]['featcnt'] = data_row['top_results'][0]['featcnt']
                software_based_summary[software_name][key]['featfreq'] = data_row['top_results'][0]['featfreq']
                software_based_summary[software_name][key]['top_results'] = data_row['top_results']
                software_based_summary[software_name][key]['package_name'].extend(data_row['package_name'])
                software_based_summary[software_name][key]['app_path'].extend(data_row['app_path'])
                software_based_summary[software_name]['app_count'] += data_row['app_count']
                software_based_summary[software_name]['uniq_app_count'] = len(software2app_set[software_name])
                if data_row['path'].endswith('.so'):
                    software_based_summary[software_name]['so_count'] += 1
                elif data_row['path'].endswith('.dex'):
                    software_based_summary[software_name]['dex_count'] += 1
                elif data_row['path'].endswith('.apk'):
                    software_based_summary[software_name]['apk_count'] += 1
                else:
                    if logger:
                        logger.error("Unknown type of matched lib: %s", data_row['name'])

            elif software_based_summary[software_name][key]['score'] < data_row['score']:
                # TODO: we never come in here
                raise Exception("Unexpected")

                print 'changing'
                print software_based_summary[software_name][key]['score']
                print data_row['score']
                software_based_summary[software_name][key]['closest_version'] = data_row['version']
                software_based_summary[software_name][key]['score'] = data_row['score']
                software_based_summary[software_name][key]['normscore'] = data_row['normscore']
                software_based_summary[software_name][key]['featcnt'] = data_row['featcnt']
                software_based_summary[software_name][key]['featfreq'] = data_row['featfreq']
            else:
                print ("ignoring version %s for %s in path %s, because of low score %s < %s" %
                       (data_row['version'], software_name, key, data_row['score'],
                        software_based_summary[software_name][key]['score']))

    if outfile:
        print ("dumping software based matched result to file %s" % outfile)
        json.dump(software_based_summary, open(outfile, 'w'), indent=2)


if __name__ == '__main__':
    kind = key_or_job = None
    if len(sys.argv) not in (3, 4, 6, 7):
        print_usage(sys.argv)
        exit(1)
    else:
        kind = sys.argv[1]
        key_or_job = sys.argv[2]
    config = appconfig.Config()

    rc = redisclient.RedisClient(config, kind)
    if not rc:
        exit(1)
    print rc.dbsize()
    print rc.memused()

    if key_or_job.lower() not in ("dump_unique", "apk_summary", "summary", "fixtemp", "monitor_indexing", "sampling",
                                  "dump_comps", "dump_popfeats", "dump_result_csv"):
        # simply query
        key = key_or_job
        if kind.lower() == 'java':
            print rc.handle().get("reposcnt")
        elif kind.lower() == 'native':
            print rc.handle().get("repos")
        elif kind.lower() == 'native_version':
            print rc.handle().get("softwareversions")
        elif kind.lower() == 'java_version':
            print rc.handle().get("softwareversionscnt")
        elif kind.lower() == 'result':
            print len(rc.handle().keys())
        else:
            raise Exception("Unexpected kind: %s" % kind)
        key_type = rc.handle().type(key)
        values = smart_get(rc.handle(), key, key_type)
        print "key %s, key type %s, values %s" % (key, key_type, values)

    elif key_or_job.lower() == "summary":
        # summarize the database
        if kind.lower() == 'java':
            for f in ("classescnt", "normclassescnt", "centroidscnt", "stringscnt", "filescnt", "dirscnt", "reposcnt"):
                print 'recorded %s count' % f, rc.handle().get(f)

            values = rc.handle().keys("files-*")
            print "files", len(values)
            values = rc.handle().keys("r-files-*")
            print "r-files", len(values)
            values = rc.handle().keys("dirs-*")
            print "dirs", len(values)
            values = rc.handle().keys("r-dirs-*")
            print "r-dirs", len(values)

        elif kind.lower() == 'native':
            for f in ("funcs", "strs", "files", "dirs", "repos"):
                print 'recorded %s count' % f, rc.handle().get(f)

            values = rc.handle().keys("file-*")
            print 'upwards, file-', len(values)
            values = rc.handle().keys("file_*")
            print 'downwards file_', len(values)
            values = rc.handle().keys("dir-*")
            print 'upwards, dir-', len(values)
            values = rc.handle().keys("dir_*")
            print 'downwards, dir_', len(values)

        elif kind.lower() in ('native_version', 'java_version'):
            values = rc.handle().keys("software-*")
            print 'total software', len(values)
            values = rc.handle().keys("softwareversiondetail-*")
            print 'total versions', len(values)
            values = rc.handle().keys("r-classes-*")
            class_count = len(values)
            print 'total files/classes', class_count
            values = rc.handle().keys("r-*")
            print 'total features', len(values) - class_count

        elif kind.lower() == 'result':
            # read the key pattern if specified
            if len(sys.argv) == 5:
                summary_file = sys.argv[3]
                key_pattern = sys.argv[4]
            elif len(sys.argv) == 4:
                summary_file = None
                key_pattern = sys.argv[3]
            else:
                key_pattern = None

            logger = applogger.Logger("Results", "/tmp/result_summary_").get()
            # get the first node's port number as suffix of the output file
            port_suffix = make_tuple(config.get('RESULT_NODES', 'RedisCluster'))[0]['port']
            # summarize result
            outfile = './software_based_summary.' + str(port_suffix) + '.json'
            summarize_result(redis_rrc=rc, logger=logger, match=key_pattern, outfile=outfile,
                             extract_summary_file=summary_file)

    elif key_or_job.lower() == 'apk_summary':
        # summarize the apk database
        so2apkfile = None
        if len(sys.argv) == 4:
            so2apkfile = sys.argv[3]
            print ("The so2apkfile mapping file is %s" % so2apkfile)
        if kind.lower() == 'result':
            # summarize result
            oss_outfile = './oss.json'
            apk_outfile = './apk.json'
            summarize_apk(redis_rrc=rc, oss_outfile=oss_outfile, apk_outfile=apk_outfile, so2apkfile=so2apkfile)
        else:
            raise Exception("Unexpected kind %s for apk_summary job! Should only be result!" % kind)

    elif key_or_job.lower() == 'dump_unique':
        # dump the number of unique features per software per version to a file
        if kind.lower() == 'java_version':
            port_suffix = make_tuple(config.get("JAVA_VERSION_NODES", "RedisCluster"))[0]['port']
        elif kind.lower() == 'native_version':
            port_suffix = make_tuple(config.get("NATIVE_VERSION_NODES", "RedisCluster"))[0]['port']
        else:
            raise Exception("Unexpected kind %s for dump_unique job! Should only be version!" % kind)
        outfile = './software_version_unique_summary.' + str(port_suffix) + '.json'
        detailfile = './software_version_unique_detail.' + str(port_suffix) + '.json'
        dump_unique(redis_vrc=rc, summaryfile=outfile, detailfile=detailfile)

    elif key_or_job.lower() == 'dump_popfeats':
        # dump the popular features to file, and sort them by popularity in descreasing order
        if kind.lower() == 'result':
            all_names = {'uniqfunc': 'func', 'func': 'func', 'uniqfuncname': 'funcname', 'funcname': 'funcname',
                         'uniqstr': 'str', 'str': 'str'}
            for name in all_names:
                outfile = './out_%s.csv' % name
                # be consistent with the dump format of searching.py
                outwriter = csv.DictWriter(open(outfile, 'w'), fieldnames=['feature', 'freq', 'type'])
                outwriter.writeheader()
                print ("start to fetch features counter for %s" % name)
                data = rc.handle().hgetall(name)
                for feat, freq in sorted(data.items(), key=lambda k: int(k[1]), reverse=True):
                    outwriter.writerow({'feature': feat, 'freq': int(freq), 'type': all_names[name]})
        else:
            raise Exception("Unexpected kind %s for dump_comps job! Should only be result!" % kind)

    elif key_or_job.lower() == 'dump_result_csv':
        # dump the result database, each key in the result database is one item, and is a hset with some fields.
        if kind.lower() == 'result':
            port_suffix = make_tuple(config.get('RESULT_NODES', 'RedisCluster'))[0]['port']
            all_keys = rc.handle().keys()
            fieldnames = ['key'] + rc.handle().hkeys(all_keys[0])
            outfile = './result_dump.' + str(port_suffix) + '.csv'
            outwriter = csv.DictWriter(open(outfile, 'w'), fieldnames=fieldnames)
            outwriter.writeheader()

            print ("start to dump %d results" % len(all_keys))
            redis_pipe = rc.pipeline()
            for result_key in all_keys:
                redis_pipe.hgetall(result_key)
            for result_key, result_dict in zip(all_keys, redis_pipe.execute()):
                try:
                    result_dict.update({'key': result_key})
                    outwriter.writerow(result_dict)
                except Exception as e:
                    print ("Error writing %s: Error %s" % (result_key, str(e)))
        else:
            raise Exception("Unexpected kind %s for dump_result_csv job! Should only be result!" % kind)

    elif key_or_job.lower() == 'dump_comps':
        # dump the key value storage for so->apk mapping and apk->so mapping
        if kind.lower() == 'result':
            so2apkfile = './so2apk.json'
            apk2sofile = './apk2so.json'
            statsfile = './apk_so_stats.json'

            so2apk_dict = {}
            apk2so_dict = {}
            # how many apk?  ->  apk_count
            # how many apk has so files?  ->  apk_with_so_count
            # how many so files does apk have on average?  -> so_counter, nz_so_counter
            # maximum so used freq  -> max_so_freq
            stats_dict = {}
            all_keys = rc.handle().keys()
            for key in all_keys:
                if key.endswith('.apk'):
                    for k, v in rc.handle().hgetall(key).items():
                        if k == 'so_count':
                            so_count = int(v)
                            stats_dict.setdefault('so_counter', [])
                            stats_dict['so_counter'].append(so_count)
                            if so_count > 0:
                                stats_dict.setdefault('nz_so_counter', [])
                                stats_dict['nz_so_counter'].append(so_count)
                                stats_dict.setdefault('apk_with_so_count', 0)
                                stats_dict['apk_with_so_count'] += 1
                        else:
                            apk2so_dict.setdefault(key, [])
                            apk2so_dict[key].append(k)

                    stats_dict.setdefault('apk_count', 0)
                    stats_dict['apk_count'] += 1
                else:
                    so2apk_dict[key] = list(rc.handle().smembers(key))
            stats_dict['max_so_freq'] = 0
            for so in so2apk_dict:
                stats_dict['max_so_freq'] = max(len(so2apk_dict[so]), stats_dict['max_so_freq'])

            # The so2apk, apk2so and stats output
            json.dump(so2apk_dict, open(so2apkfile, 'w'), indent=2)
            json.dump(apk2so_dict, open(apk2sofile, 'w'), indent=2)
            json.dump(stats_dict, open(statsfile, 'w'), indent=2)

        else:
            raise Exception("Unexpected kind %s for dump_comps job! Should only be result!" % kind)

    elif key_or_job.lower() == "fixtemp":
        # fix temporary errors in database
        # pipeline can optimize the performance though
        if len(sys.argv) == 6:
            name, key, value = sys.argv[3:]
            rc.handle().hset(name, key, value)

            # XXX: Hack, used to remove failure nodes in native!
            # all_keys = rc.handle().keys()
            # redis_pipe = rc.pipeline()
            # for key in all_keys:
            #    redis_pipe.hget(key, 'repo_matches')
            # fix_count = 0
            # for key, match_count in zip(all_keys, redis_pipe.execute()):
            #    if match_count is None or int(match_count)  < 0:
            #        rc.handle().delete(key)
            #        fix_count += 1
            # print ("fixed %d failure redis records!" % fix_count)

        else:
            remove_kv_pair = {}

            # get all key types
            redis_pipe = rc.pipeline()
            key_list = rc.handle().keys()
            for key in key_list:
                redis_pipe.type(key)
            key_type_list = redis_pipe.execute()
            print "get all %d key types" % len(key_list)

            pipeline = False

            if pipeline:
                # get all hash key
                hash_key_list = []
                for key, key_type in izip(key_list, key_type_list):
                    if key_type == "hash":
                        hash_key_list.append(key)
                        redis_pipe.hgetall(key)
                print "get all %d hash key" % len(hash_key_list)

                # get all hash key values
                hash_key_value_list = redis_pipe.execute()
                for hash_key, hash_key_value in izip(hash_key_list, hash_key_value_list):
                    for v, score in hash_key_value.items():
                        # We will have negative value problem only for files and directories, i.e. the map targets
                        # files- and dirs- are for Java, file- and dir- are for Native
                        if v.startswith(("files-", "dirs-", "file-", "dir-")) and score <= 0:
                            remove_kv_pair.setdefault(hash_key, [])
                            remove_kv_pair[hash_key].append(v)
                print "get all hash key values, with remove_kv_pair size: %d" % len(remove_kv_pair)

                # print the problematic keys
                # print remove_kv_pair
                print ({k: len(v) for k, v in remove_kv_pair.items()})
                response = raw_input("Do you want to remove these problematic key value paris yes/no? [no]")
                if response.lower() == 'yes':
                    for k, value_list in remove_kv_pair.items():
                        redis_pipe.hdel(k, value_list)
                redis_pipe.execute()
                print ("removed problematic key value pairs for %d keys!" % len(remove_kv_pair))
            else:
                redis = rc.handle()
                for key, key_type in izip(key_list, key_type_list):
                    if key_type == "hash":
                        key_items = redis.hgetall(key)
                        for v, score in key_items.items():
                            if v.startswith(("files-", "dirs-", "file-", "dir-")) and score <= 0:
                                remove_kv_pair.setdefault(key, [])
                                remove_kv_pair[key].append(v)
                                redis.hdel(key, v)
                print ("removed problamtic key values pairs for %d keys!" % len(remove_kv_pair))

    elif key_or_job.lower() == "monitor_indexing":
        import csv

        fieldnames = ['time', 'time_ymdhms', 'memory_size', 'keys', 'repos', 'versions']
        outfile = '/tmp/monitor_indexing_' + time.strftime('%Y_%m_%d_%H_%M_%S') + '.csv'
        outf = open(outfile, 'w')
        outwriter = csv.DictWriter(outf, fieldnames=fieldnames)
        outwriter.writeheader()
        try:
            while True:
                keys = rc.dbsize()[0]
                if kind.lower() == 'java':
                    repos = rc.handle().get("reposcnt")
                    versions = ''
                elif kind.lower() == 'native':
                    repos = rc.handle().get("repos")
                    versions = ''
                elif kind.lower() == 'native_version':
                    repos = rc.handle().get("softwares")
                    versions = rc.handle().get("softwareversions")
                elif kind.lower() == 'java_version':
                    repos = rc.handle().get("softwarescnt")
                    versions = rc.handle().get("softwareversionscnt")
                elif kind.lower() == 'result':
                    repos = len(rc.handle().keys())
                    versions = ''
                memory_size = rc.memused()[0]
                time_seconds = time.time()
                time_ymdhms = time.strftime('%Y-%m-%d %H:%M:%S')
                outwriter.writerow({'time': time_seconds, 'time_ymdhms': time_ymdhms, 'memory_size': memory_size,
                                    'keys': keys, 'repos': repos, 'versions': versions})
                outf.flush()
                time.sleep(5)
        except:
            outf.close()
            raise

    elif key_or_job.lower() == "sampling":
        if kind.lower() == 'result':
            key_pattern = None
            sample_count = 100
            if len(sys.argv) == 4:
                sample_count = sys.argv[3]
            elif len(sys.argv) == 5:
                sample_counter = sys.argv[3]
                key_pattern = sys.argv[4]
            if key_pattern:
                all_keys = rc.handle().keys(key_pattern)
            else:
                all_keys = rc.handle().keys()
            import random

            random.shuffle(all_keys)

            # dump the result
            port_suffix = make_tuple(config.get("RESULT_NODES", "RedisCluster"))[0]['port']
            outfile = "sampling_count_%s.%s.json" % (sample_count, port_suffix)
            result_dict = {}
            counter = 0
            for key in all_keys:
                if int(rc.handle().hget(key, "repo_matches")) >= 0:
                    result_dict[key] = rc.handle().hgetall(key)
                    counter += 1
                if counter >= sample_count:
                    break
            json.dump(result_dict, fp=open(outfile, 'w'), indent=2)
        else:
            raise Exception("Unexpected kind %s for dump_unique job! Should only be result!" % kind)

    else:
        raise Exception("Unhandled job %s" % key_or_job)
