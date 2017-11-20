import os
import csv
import utils
import time
from os.path import exists, join, basename
from job_util import read_proto_from_file
from extractor.extract_from_compressed_files import run_extractor_worker
from extractor.util.proto.repo_detail_pb2 import ExtractConfig, DEX, SO
from extractor.util.license_util import get_license_info


###########################################################
# init state
###########################################################
logger = None
stats_logger = None
COMPONENTS_SUFFIX = ".components"


def get_license_info_wrapper(filename=None, file_content=None, prefix='license-info-'):
    return get_license_info(filename=filename, file_content=file_content, prefix=prefix)


def load_extract_result(proto_path, binary=False):
    extract_config = ExtractConfig()
    read_proto_from_file(proto=extract_config, filename=proto_path, binary=binary)
    so_paths = []
    dex_paths = []
    for component in extract_config.components:
        if component.component_type == DEX:
            dex_paths.append(component.store_path)
        elif component.component_type == SO:
            so_paths.append(component.store_path)
    return {"so": so_paths, "dex": dex_paths}


def extract_apk(main, input_path, load_result=False, store_redis=True):
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger

    logger.info("Extracting app %s to %s", input_path, main.RESULT_DIR)

    outdir = main.RESULT_DIR
    expected_outfile = join(outdir, basename(input_path) + COMPONENTS_SUFFIX)
    if main.reuse_sig and exists(expected_outfile):
        # loading existing expected outfile
        outfile = expected_outfile
        logger.info("Reusing previously generated components file: %s", expected_outfile)
    else:
        # extract so files from the apk
        try:
            # extract_types can be ['DEX', 'SO'] or ['SO'], depending on the implementation in proj-crawler!
            outfile = run_extractor_worker(input_path, outdir, extract_types=['SO'], in_type='APK',
                                           store_type="file_with_symlink", skip_processed=False, binary=False)
        except Exception as e:
            logger.error("Error extracting components from %s: %s", input_path, str(e))
            outfile = None

    if main.rrc or load_result:
        result = load_extract_result(proto_path=outfile, binary=False)
        if main.rrc and store_redis:
            redis_rrc = main.rrc.handle()
            # store the mapping into the rrc database!
            so_dict = {so: 1 for so in result['so']}
            redis_rrc.hset(input_path, 'so_count', len(so_dict))
            if so_dict:
                redis_rrc.hmset(input_path, so_dict)
                for store_path in so_dict:
                    redis_rrc.sadd(store_path, input_path)
        return result
    else:
        return outfile


def skip_input(main, input_path):
    expected_outfile = join(main.RESULT_DIR, basename(input_path) + COMPONENTS_SUFFIX)
    if main.ignore_scanned and exists(expected_outfile):
        return True
    else:
        return False


def get_input_list(main, input_list_file, skip_input_callback=None):
    # Check field
    reader = csv.DictReader(open(input_list_file, 'r'))
    field = utils.any_and_return(['inpath', 'input_path', 'app_path', 'downloaded_path'], reader.fieldnames)
    if not field:
        if logger:
            logger.error("No input field was found in %s", input_list_file)
        exit(1)

    input_list = []
    for row in reader:
        if row[field] and skip_input_callback and not skip_input_callback(main=main, input_path=row[field]):
            input_list.append(row[field])
        else:
            if logger:
                logger.info("Skipping: %s", row[field])
    return input_list


###########################################################
# Extracting
###########################################################
def run_extractor(main, argv):
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger

    if not len(argv) == 1:
        logger.error('expects args: $apk_list, but get: %s', argv)
        exit(1)

    input_path = argv[0]
    if not os.path.exists(input_path):
        logger.error("%s does not exist", input_path)
        exit(1)

    if not main.RESULT_DIR:
        logger.error("Result directory not available!")
    elif not exists(main.RESULT_DIR):
        logger.info("Creating directory: %s", main.RESULT_DIR)
        os.makedirs(main.RESULT_DIR)

    input_list = get_input_list(main=main, input_list_file=input_path, skip_input_callback=skip_input)
    # deduplicate!
    input_list = list(set(input_list))

    # start extracting
    if input_list:
        # track progress
        count = len(input_list)
        logger.info("Extracting %d apks", count)

        # register signal handler
        signal = utils.Signal()
        signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

        pb = utils.Progressbar("Extracting apks: ", count)
        pb.start()

        if main.QUEUING and main.QUEUING == "Celery":
            from celery import group
            from celery_tasks import extract_apk_worker

            # group jobs
            job = group(extract_apk_worker.s(infile) for infile in input_list)
            result = job.apply_async()

            # track worker progress
            completed = 0
            while result.waiting():
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

                if extract_apk(main, infile):
                    count += 1

                # update progressbar
                pb.update(count)

            if not signal.caught():
                pb.finish()
