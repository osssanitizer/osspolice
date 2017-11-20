import os
import time
import utils
import csv
from os.path import exists, join, basename, splitext, getsize
from extract_apk import get_input_list
from itertools import chain

###########################################################
# init state
###########################################################
logger = None
stats_logger = None


def get_input_and_type_field(fieldnames):
    input_field = utils.any_and_return(test_fields=['feature', 'strings', 'functions'], target_fields=fieldnames)
    type_field = utils.any_and_return(test_fields=['type', 'typ', 'feature_type'], target_fields=fieldnames)
    if not input_field or not type_field:
        logger.error("input field or type field doesn't exist in %s", fieldnames)
    return (input_field, type_field)


def get_freq_field(fieldnames):
    freq_field = utils.any_and_return(test_fields=['freq', 'feature_freq', 'featfreq'], target_fields=fieldnames)
    if not freq_field:
        logger.error("freq field doesn't exist in %s", fieldnames)
    return freq_field


def subtract_features(main, input_path, write_filtered_csv=False):
    redis = main.rrc.handle()

    all_features = {}
    filtered_features = {}
    # for checked type fields
    for typ in ['str', 'func', 'funcname']:
        all_features.setdefault(typ, [])
        filtered_features.setdefault(typ, [])

    # load common features
    common_features_reader = csv.DictReader(open(main.common_feature_file, 'r'))
    common_input_field, common_type_field = get_input_and_type_field(common_features_reader.fieldnames)
    common_features = {}
    for row in common_features_reader:
        common_features.setdefault(row[common_type_field], set())
        common_features[row[common_type_field]].add(row[common_input_field])

    # load features from file and filter them
    reader = csv.DictReader(open(input_path, 'r'))
    if len(reader.fieldnames) == 0:
        logger.info("skipping empty csv file: %s", input_path)
        return

    input_field, type_field = get_input_and_type_field(reader.fieldnames)
    freq_field = get_freq_field(reader.fieldnames)

    for row in reader:
        row[freq_field] = int(row[freq_field])
        all_features.setdefault(row[type_field], [])
        all_features[row[type_field]].append(row)

    for row in chain(*all_features.values()):
        if row[type_field] in common_features and row[input_field] in common_features[row[type_field]]:
            logger.debug("filtered feat %s, type %s from input %s", row[input_field], row[type_field], input_path)
        else:
            # for unknown type fields
            filtered_features.setdefault(row[type_field], [])
            filtered_features[row[type_field]].append(row)

    for typ in all_features:
        logger.info("filtered %d %s features into %d features using common features",
                    len(all_features[typ]), typ, len(filtered_features[typ] if typ in filtered_features else 0))

    # so size information
    lib_size = expected_lib_path = None
    if main.comp_sig_load_dirs:
        for comp_sig_load_dir in main.comp_sig_load_dirs:
            expected_lib_path = join(comp_sig_load_dir, splitext(input_path)[0].split('search_dump_')[-1])
            if exists(expected_lib_path):
                lib_size = getsize(expected_lib_path)
        if lib_size is None:
            logger.error("cannot find the orig library file %s for feature dump file %s", expected_lib_path, input_path)
    else:
        logger.error("comp_sig_load_dirs not available!")

    strcount = len(filtered_features['str'])

    # func is for C++ functions, funcname is for C functions
    cfunccount = len(filtered_features['funcname'])
    cppfunccount = len(filtered_features['func'])
    filtered_features['allfunc'] = filtered_features['func'] + filtered_features['funcname']
    all_features['allfunc'] = all_features['func'] + all_features['funcname']

    # filtered by popular
    funccount = len(filtered_features['allfunc'])

    # no filter at all
    allfunccount = len(all_features['allfunc'])

    javacom_funccount = len([row for row in filtered_features['allfunc'] if row[input_field].startswith('Java_com_')])

    # filtered by popular and javacom
    nojavacom_funccount = funccount - javacom_funccount

    logger.info(
        "num strings %d, num funcs %d (c: %d, c++: %d), total %d, num all funcs %d, num java_com funcs %d, num non-java_com funcs %d",
        strcount, funccount, cfunccount, cppfunccount, strcount + funccount, allfunccount, javacom_funccount,
        nojavacom_funccount)
    redis.hmset(input_path, {'strcount': strcount, 'funccount': funccount, 'total': strcount + funccount,
                             'cfunccount': cfunccount, 'cppfunccount': cppfunccount,
                             'allfunccount': allfunccount, 'javacom_funccount': javacom_funccount,
                             'nojavacom_funccount': nojavacom_funccount,
                             'size': lib_size, 'lib_path': expected_lib_path})

    if write_filtered_csv:
        # write the filtered features back to file
        outfile = join(main.RESULT_DIR, basename(input_path))
        writer = csv.DictWriter(open(outfile, 'w'), fieldnames=reader.fieldnames)
        writer.writeheader()
        for typ in filtered_features:
            for row in filtered_features[typ]:
                writer.writerow(row)


def count_features(main, input_path):
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger

    # if common feature file has been generated, then update the feature file accordingly, o.w. count the features
    if main.common_feature_file and exists(main.common_feature_file):
        logger.info("Subtracting common features from %s", input_path)
        subtract_features(main, input_path)

    else:
        logger.info("Counting features from %s", input_path)

        redis_pipe = main.rrc.pipeline()
        reader = csv.DictReader(open(input_path, 'r'))
        # field names: [type, freq, feature]
        input_field = utils.any_and_return(test_fields=['feature', 'strings', 'functions'],
                                           target_fields=reader.fieldnames)
        type_field = utils.any_and_return(test_fields=['type', 'typ', 'feature_type'], target_fields=reader.fieldnames)
        freq_field = utils.any_and_return(test_fields=['freq', 'frequency', 'feature_freq'],
                                          target_fields=reader.fieldnames)
        if not input_field or not type_field:
            logger.error("input field or type field doesn't exist in %s", reader.fieldnames)
            return

        type2count = {}
        type2count.setdefault('func', 0)
        type2count.setdefault('uniqfunc', 0)
        for row in reader:
            feature_value = row[input_field]
            feature_type = row[type_field]
            type2count.setdefault('uniq' + feature_type, 0)
            type2count['uniq' + feature_type] += 1
            if main.feature_key_type == 'hset':
                redis_pipe.hincrby('uniq' + feature_type, feature_value, 1)
            elif main.feature_key_type == 'zset':
                redis_pipe.zincrby('uniq' + feature_type, feature_value, 1)
            else:
                logger.error("Unexpected feature_key_type %s!", main.feature_key_type)
                return

            if freq_field:
                feature_freq = row[freq_field]
                type2count.setdefault(feature_type, 0)
                type2count[feature_type] += int(feature_freq)
                if main.feature_key_type == 'hset':
                    redis_pipe.hincrby(feature_type, feature_value, int(feature_freq))
                elif main.feature_key_type == 'zset':
                    redis_pipe.zincrby(feature_type, feature_value, int(feature_freq))
                else:
                    logger.error("Unexpected feature_key_type %s!", main.feature_key_type)

        redis_pipe.hmset(input_path, type2count)
        try:
            redis_pipe.execute()
            logger.info("Finished counting features from %s", input_path)
        except Exception as e:
            logger.error("Error processing input file %s: %s", input_path, str(e))


def skip_input(main, input_path):
    redis = main.rrc.handle()
    if main.ignore_scanned and redis.exists(input_path):
        return True
    else:
        return False


###########################################################
# Counting
###########################################################
def run_counter(main, argv):
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger

    if not len(argv) == 1:
        logger.error('expects args: $feature_csv_list, but get: %s', argv)
        exit(1)

    input_path = argv[0]
    if not os.path.exists(input_path):
        logger.error("%s does not exist", input_path)
        exit(1)

    redis_rrc = main.rrc
    if not redis_rrc or not redis_rrc.handle():
        logger.error("redis rrc not available, exiting!")
        exit(1)

    input_list = get_input_list(main=main, input_list_file=input_path, skip_input_callback=skip_input)
    # deduplicate!
    input_list = list(set(input_list))

    # start extracting
    if input_list:
        # track progress
        count = len(input_list)
        logger.info("Counting %d feature files", count)

        # register signal handler
        signal = utils.Signal()
        signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

        pb = utils.Progressbar("Counting features: ", count)
        pb.start()

        if main.QUEUING and main.QUEUING == "Celery":
            from celery import group
            from celery_tasks import feature_counter_worker

            # group jobs
            job = group(feature_counter_worker.s(infile) for infile in input_list)
            result = job.apply_async()

            # track worker progress
            completed = 0
            while (result.waiting()):
                completed += result.completed_count()
                if completed < count:
                    pb.update(completed)
                time.sleep(2)

        else:  # non-parallel instance
            count = 0
            # scan loop
            for infile in input_list:
                # check for interruption
                if signal.caught():
                    break
                if count_features(main, infile):
                    count += 1
                # update progressbar
                pb.update(count)

            if not signal.caught():
                pb.finish()
