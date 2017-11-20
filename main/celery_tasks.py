#!/usr/bin/env python

import os
import logging
import detector as main
import logger as applogger
try:
    import indexing
    import searching
    import signature
except Exception as e:
    print("Error importing C/C++ related code (indexing or searching): %s" % str(e))
try:
    import indexing_java
    import searching_java
    import signature_java
except Exception as e:
    print("Error importing Java related code (indexing/searching/signaturing): %s" % str(e))
try:
    import searching_apk
    import extract_apk
    import feature_count
    import validate
except Exception as e:
    print("Error importing APK/Extraction/Validation/Stats related code: %s" % str(e))

from celery import Celery
from celery.signals import task_prerun
from celery.signals import after_setup_task_logger
from celery.exceptions import WorkerLostError


###########################################################
# init state
###########################################################
detector = main.Detector("Celery")
if not detector:
     print "Celery failed to init detector!"
     exit(1)
broker = detector.CELERY_BROKER_URL
backend = detector.CELERY_RESULTS_BACKEND
app = Celery('celery_tasks', broker=broker, backend=backend)
app.config_from_object('celery_config')  # use custom config file
logger = None


###########################################################
# Init
###########################################################
def init_task(**kwargs):
    if not detector:
        exit(1)


###########################################################
# Logger
###########################################################
def setup_logging(**kw):
    global logger
    logger = detector.logger
    logger.propagate = False


###########################################################
# TASK to index repos
###########################################################
#@app.task(bind=True, acks_late=True, time_limit=3600)
#@app.task(time_limit=7200, acks_late=True)  # set the timeout back to 2 hours
@app.task(time_limit=43200, acks_late=True)  # set the timeout to 12 hours
def native_indexing_worker(repo_path, repo_id, branch, test):
    try:
        # if we are just testing this repo
        if test == 'dump' or test == 'stats':
            detector.TEST_REPO = True
        if test == 'stats':
            detector.STATS = True

        num_strs = indexing.index_repo(main=detector, root_repo_path=repo_path, item=repo_id, branch=branch)
        return num_strs
    except WorkerLostError as wle:
        logger.error("native_indexing_worker: %s", str(wle))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(repo_path + '\n')
        return 0
    except Exception as e:
        logger.error("native_indexing_worker: %s", str(e))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(repo_path + '\n')
        return 0


###########################################################
# TASK to match lib
###########################################################
#@app.task(bind=True, acks_late=True, time_limit=3600)
#@app.task(bind=True, time_limit=7200)
@app.task(time_limit=7200, acks_late=True)
def native_search_worker(lib_path, test):
    try:
        # if we are just testing this lib
        if test == 'dump' or test == 'stats':
            detector.TEST_LIB = True
        if test == 'stats':
            detector.STATS = True

        count = searching.search_library(detector, lib_path)
        return count
    except WorkerLostError as wle:
        logger.error("native_search_worker: %s", str(wle))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(lib_path + '\n')
        return 0
    except Exception as e:
        logger.error("native_search_worker: %s", str(e))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(lib_path + '\n')
        return 0


###########################################################
# TASK to dump repo features/signatures
###########################################################
@app.task(time_limit=43200, acks_late=True)
def native_signature_worker(repo_path, repo_id, branch, test):
    try:
        # if we are just testing this repo
        if test == 'dump' or test == 'stats':
            detector.TEST_REPO = True
        if test == 'stats':
            detector.STATS = True

        signature.signature_repo(main=detector, root_repo_path=repo_path, item=repo_id, branch=branch)
    except WorkerLostError as wle:
        logger.error("native_signature_worker: %s", str(wle))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(repo_path + '\n')
        return 0
    except Exception as e:
        logger.error("native_signature_worker: %s", str(e))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(repo_path + '\n')
        return 0


###########################################################
# TASK to index java related files, class/jar/dex/apk
###########################################################
@app.task(bind=True, time_limit=3600)
def index_java_worker(self, input_path, input_type='jar'):
    try:
        indexing_java.index_classes(main=detector, input_path=input_path, input_type=input_type)
    except WorkerLostError as wle:
        logger.error("index_java_worker: %s", str(wle))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(input_path + '\n')
        return 0
    except Exception as e:
        logger.error("index_java_worker: %s", str(e))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(input_path + '\n')
        return 0


###########################################################
# TASK to match java related files, class/jar/dex/apk
###########################################################
@app.task(bind=True, time_limit=3600)
def search_java_worker(self, input_path, input_type='dex'):
    try:
        searching_java.search_classes(main=detector, input_path=input_path, input_type=input_type)
    except WorkerLostError as wle:
        logger.error("search_java_worker: %s", str(wle))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(input_path + '\n')
        return 0
    except Exception as e:
        logger.error("search_java_worker: %s", str(e))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(input_path + '\n')
        return 0


###########################################################
# TASK to extract signature for java related files, class/jar/dex/apk
###########################################################
@app.task(bind=True, time_limit=3600)
def signature_java_worker(self, input_path, input_type='dex'):
    try:
        signature_java.signature_classes(main=detector, input_path=input_path, input_type=input_type)
    except WorkerLostError as wle:
        logger.error("signature_java_worker: %s", str(wle))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(input_path + '\n')
        return 0
    except Exception as e:
        logger.error("signature_java_worker: %s", str(e))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(input_path + '\n')
        return 0


###########################################################
# TASK to search an app, to see whether it is matching some OSS, and get the matched version!
###########################################################
@app.task(bind=True, time_limit=3600)
def search_apk_worker(self, input_path):
    try:
        searching_apk.search_apk(main=detector, input_path=input_path)
    except WorkerLostError as wle:
        logger.error("search_apk_worker: %s", str(wle))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(input_path + '\n')
        return 0
    except Exception as e:
        logger.error("search_apk_worker: %s", str(e))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(input_path + '\n')
        return 0


###########################################################
# TASK to extract components from an app, e.g., so libs and dex binaries
###########################################################
@app.task(bind=True, time_limit=3600)
def extract_apk_worker(self, input_path):
    try:
        extract_apk.extract_apk(main=detector, input_path=input_path)
    except WorkerLostError as wle:
        logger.error("extract_apk_worker: %s", str(wle))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(input_path + '\n')
        return 0
    except Exception as e:
        logger.error("extract_apk_worker: %s", str(e))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(input_path + '\n')
        return 0


###########################################################
# TASK to count features by loading from csv files
###########################################################
@app.task(bind=True, time_limit=10800)
def validate_worker(self, app_path):
    try:
        validate.validate_apk(main=detector, app_path=app_path)
    except WorkerLostError as wle:
        logger.error("validate_worker: %s", str(wle))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(app_path + '\n')
        return 0
    except Exception as e:
        logger.error("validate_worker: %s", str(e))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(app_path + '\n')
        return 0


###########################################################
# TASK to count features by loading from csv files
###########################################################
@app.task(bind=True, time_limit=3600)
def feature_counter_worker(self, input_path):
    try:
        feature_count.count_features(main=detector, input_path=input_path)
    except WorkerLostError as wle:
        logger.error("feature_counter_worker: %s", str(wle))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(input_path + '\n')
        return 0
    except Exception as e:
        logger.error("feature_counter_worker: %s", str(e))
        if detector.failure_file and os.path.exists(detector.failure_file):
            open(detector.failure_file, 'a').write(input_path + '\n')
        return 0


# need to use registered instance for sender argument.
task_prerun.connect(init_task)
after_setup_task_logger.connect(setup_logging)
