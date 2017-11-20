#!/usr/bin/env python

import os
import searching
import searching_java
import utils
import time
from os.path import join, basename
from signature_java import get_input_list

###########################################################
# init state
###########################################################
logger = None
stats_logger = None


###########################################################
# This program takes apks as input and extract shared library (so).
# Then query apk against java redis database to find matches,
# and query so against redis database to find matches.
# Output matches
###########################################################
def extract_componnets(main, input_path):
    from extract_apk import COMPONENTS_SUFFIX, load_extract_result, extract_apk
    # expected components file
    expected_outname_exists = False
    expected_outname = None
    if main.comp_sig_load_dirs:
        for d in main.comp_sig_load_dirs:
            expected_outname = join(d, basename(input_path) + COMPONENTS_SUFFIX)
            if os.path.exists(expected_outname):
                expected_outname_exists = True
                break
    if expected_outname_exists:
        extracted = load_extract_result(proto_path=expected_outname, binary=False)
    else:
        from detector import Detector
        extract_main = Detector(mode="ApkExtract")
        if main.comp_sig_load_dirs:
            extract_main.RESULT_DIR = main.comp_sig_load_dirs[0]
        # load the extracted components, but skip the step to store them in redis.
        extracted = extract_apk(main=extract_main, input_path=input_path, load_result=True, store_redis=False)
    return extracted


def search_apk(main, input_path):
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger

    search_results = {}

    # For native search, get the native components within this app and search them one by one
    logger.info("searching the native part of %s now!", input_path)
    so_paths = extract_componnets(main, input_path)["so"]
    logger.info("found %d native libraries!", len(so_paths))
    if len(so_paths):
        from searching import search_library
        for lib_path in so_paths:
            logger.info("searching the native library %s of %s now!", lib_path, input_path)
            if main.MODE == "Celery":
                native_main = main
            else:
                from detector import Detector
                native_main = Detector(mode="Searching")
            native_result = search_library(main=native_main, lib_path=lib_path)
            search_results[lib_path] = native_result

    # For java search, directly invoke search java worker
    logger.info("searching the java part of %s now!", input_path)
    from searching_java import search_classes
    if main.MODE == "Celery":
        java_main = main
    else:
        from detector import Detector
        java_main = Detector(mode="JavaSearching")
    java_result = search_classes(main=java_main, input_path=input_path, input_type='apk')
    search_results[input_path] = java_result

    # Map the apk to so files
    main.rrc.handle().hset(input_path, 'so_paths', so_paths)
    logger.info("Finished querying app: %s, and the results are: %s", input_path, search_results)


###########################################################
# Searcher
###########################################################
def run_searcher(main, argv):
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger
    searching.logger = main.logger
    searching.stats_logger = main.stats_logger
    searching_java.logger = main.logger
    searching_java.stats_logger = main.stats_logger

    if len(argv) != 2:
        logger.error('expects two args')
        exit(1)

    # if we are just testing this repo
    if argv[0] == 'dump':
        main.TEST_REPO = True

    # check if redis is populated
    ndbsize, ndbval = main.nrc.dbsize()
    jdbsize, jdbval = main.jrc.dbsize()
    rdbsize, rdbval = main.rrc.dbsize()
    if ndbsize == 0 or jdbsize == 0:
        logger.error("Nothing is indexed in native or java redis db (ndbsize: %s, jdbsize: %s, rdbsize: %s)! Exiting.",
                     ndbsize, jdbsize, rdbsize)
        exit(1)

    # check if path exists
    input_path = argv[1]
    if not os.path.exists(input_path):
        logger.error('%s does not exist', input_path)
        exit(1)

    apk_list = get_input_list(main=main, redis=main.rrc, redis_pipe=main.rrc.pipeline(), input_path=input_path,
                              input_type="apk", skip_scanned=True, skip_failure=True)

    print ("There are %d input to be searched" % len(apk_list))
    # start searching
    if apk_list:

        # register signal handler
        signal = utils.Signal()
        signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

        # track progress
        count = len(apk_list)
        logger.info("Searching %d applications", count)
        pb = utils.Progressbar('Matching libs: ', count)
        pb.start()

        # if requested parallelism
        if main.QUEUING and main.QUEUING == "Celery":
            from celery import group
            from celery_tasks import search_apk_worker

            # group jobs
            job = group(search_apk_worker.s(app_path) for app_path in apk_list)
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
            for app_path in apk_list:

                # check for interruption
                if signal.caught():
                    break

                # lookup apk
                search_apk(main, app_path)

                # update progressbar
                count += 1
                pb.update(count)

            # all done
            if not signal.caught() and pb:
                pb.finish()

    else:
        logger.error("No apk(s) to search")
