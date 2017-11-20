#!/usr/bin/env python

import config as appconfig
import logger as applogger
import redisclient
import json
import cProfile
from ast import literal_eval

###########################################################
# Celery config
###########################################################
def celery_check(main):
    '''
    Function to check if Celery workers are up and running.
    '''
    try:
        from celery import Celery
        broker = main.CELERY_BROKER_URL
        backend = main.CELERY_RESULTS_BACKEND
        app = Celery('celery_tasks', broker=broker, backend=backend)
        app.config_from_object('celery_config')
        if not app.control.inspect().stats() and not app.control.inspect().ping():
            raise Exception("Start celery workers. None running.")
        return True

    except IOError as e:
        msg = "Error connecting to the backend: " + str(e)
        from errno import errorcode
        if len(e.args) > 0 and errorcode.get(e.args[0]) == 'ECONNREFUSED':
            raise Exception("Check that the RabbitMQ server is running.")

    except ImportError as e:
        raise Exception("Celery module not available. Please install")


###########################################################
# Usage
###########################################################
def print_usage(argv):
    print 'usage: ./%s [options] <path to dir containing shared libs>' % argv[0]
    print 'options:'
    print '\t --log-stats: log statistics'
    print '\t --test-lib: dump all extracted strings'
    print '\t --min-len: consider all strings with length >= this length'


###########################################################
# Main function
###########################################################
class Detector(object):

    def __init__(self, mode, config_path='config'):

        self.USE_REGEX = True
        self.TEST_REPO = None
        self.TEST_LIB = None
        self.STATS = None
        self.VERBOSE = None
        self.LOG_PER_FILE = None
        self.REPO_SOURCE = None
        self.REPO_ROOT_URL = None
        self.CELERY_BROKER_URL = None
        self.CELERY_RESULT_BACKEND = None
        self.REPO_CLONE_RETRIES = 0
        self.REPO_CLONE_TIMEOUT = 10
        self.REPO_SUBMODULE_TIMEOUT = 10
        self.MIN_SIZE_C_CPP_FILES = None
        self.MAX_SIZE_C_CPP_FILES = None
        self.INDEX_REPO_VERSIONS = False
        self.INDEX_SUBMODULES = False
        self.MODE = mode
        self.SCAN_FILES_FOR_LICENSE = False
        self.RESULT_DIR = '/tmp'

        # get configuration
        config = appconfig.Config(file_path=config_path)
        if not config:
            exit(1)

        # logging infrastructure
        logfile_prefix = config.get("LOGFILE_PREFIX", mode)
        self.logfile_prefix = logfile_prefix
        logger = None
        try:
            logger = applogger.Logger("Results", logfile_prefix).get()
        except Exception as e:
            print "Error setting up 'Results' logger: %s" % (str(e))
            exit(1)

        self.config = config
        self.logger = logger

        ###########################################################
        # Infrastructure check
        ###########################################################
        # check for configured key-value store
        kv_store = config.get("KV_STORE", "Infrastructure")
        if not kv_store:
            logger.error("KV_STORE missing from config! Ignoring")
            self.nrc = self.jrc = self.nvrc = self.jvrc = self.rrc = None
        # validate specified key-value store
        elif kv_store != "Redis":
            logger.error("Unsupported KV_STORE type: %s", kv_store)
            exit(1)
        else:
            # check if redis is working
            try:
                """
                nrc -> native nodes, nvrc -> native version nodes,
                jrc -> java nodes, jvrc -> java version nodes,
                rrc -> result nodes
                """
                self.nrc = self.jrc = self.nvrc = self.jvrc = self.rrc = None
                # readonly is True for searching, False for indexing
                # readonly is depends on the configuration for Celery
                readonly = False if mode in ("Indexing", "JavaIndexing") else True
                if mode in ("Indexing", "Searching", "Signature"):
                    # TODO: Signature doesn't need redis client, remove it from signature.py
                    if mode in ("Indexing", "Searching"):
                        self.nrc = redisclient.RedisClient(config, kind="NATIVE", logger=logger, readonly=readonly)
                        self.nvrc = redisclient.RedisClient(config, kind="NATIVE_VERSION", logger=logger, readonly=readonly)
                    if mode == "Searching":
                        self.rrc = redisclient.RedisClient(config, kind="RESULT", logger=logger, readonly=False)
                elif mode in ("JavaSearching", "JavaIndexing", "JavaSignature"):
                    # TODO: JavaSignature doesn't need redis client, remove it from signature_java.py
                    if mode in ("JavaSearching", "JavaIndexing"):
                        self.jrc = redisclient.RedisClient(config, kind="JAVA", logger=logger, readonly=readonly)
                        self.jvrc = redisclient.RedisClient(config, kind="JAVA_VERSION", logger=logger, readonly=readonly)
                    if mode == "JavaSearching":
                        self.rrc = redisclient.RedisClient(config, kind="RESULT", logger=logger, readonly=False)
                elif mode == "Celery":
                    # In celery mode, the redis database can be readonly or writeable
                    val = config.get("REDIS_READONLY_MODE", mode)
                    readonly = self.str2bool(val) if val else False
                    # In celery mode, redis database maybe missing!
                    self.nrc = redisclient.RedisClient(config, kind="NATIVE", logger=logger, readonly=readonly)
                    self.nvrc = redisclient.RedisClient(config, kind="NATIVE_VERSION", logger=logger, readonly=readonly)
                    self.jrc = redisclient.RedisClient(config, kind="JAVA", logger=logger, readonly=readonly)
                    self.jvrc = redisclient.RedisClient(config, kind="JAVA_VERSION", logger=logger, readonly=readonly)
                    self.rrc = redisclient.RedisClient(config, kind="RESULT", logger=logger, readonly=False)
                elif mode == "Dumping":
                    self.jrc = redisclient.RedisClient(config, kind="JAVA", logger=logger, readonly=readonly)
                    self.nrc = redisclient.RedisClient(config, kind="NATIVE", logger=logger, readonly=readonly)
                elif mode == "ApkSearching":
                    self.nrc = redisclient.RedisClient(config, kind="NATIVE", logger=logger, readonly=readonly)
                    self.nvrc = redisclient.RedisClient(config, kind="NATIVE_VERSION", logger=logger, readonly=readonly)
                    self.jrc = redisclient.RedisClient(config, kind="JAVA", logger=logger, readonly=readonly)
                    self.jvrc = redisclient.RedisClient(config, kind="JAVA_VERSION", logger=logger, readonly=readonly)
                    self.rrc = redisclient.RedisClient(config, kind="RESULT", logger=logger, readonly=False)
                elif mode == "ApkExtract":
                    # if we want to cache the apk to so and so to apk mapping, we want to use the result database
                    self.rrc = redisclient.RedisClient(config, kind="RESULT", logger=logger, readonly=False)
                elif mode == "FeatureCounting":
                    self.rrc = redisclient.RedisClient(config, kind="RESULT", logger=logger, readonly=False)
                elif mode == "Validate":
                    self.rrc = redisclient.RedisClient(config, kind="RESULT", logger=logger, readonly=False)
                else:
                    raise Exception("Invalid mode " + mode)

            except Exception as e:
                logger.error("Error setting up redis: %s", str(e))
                exit(1)

            # redis client handle
            if self.nrc and self.nrc.specified() and not self.nrc.handle():
                logger.error("Native redis client not available! Exiting.")
                exit(1)

            if self.nvrc and self.nvrc.specified() and not self.nvrc.handle():
                logger.error("Native version redis client not available! Exiting.")
                exit(1)

            if self.jrc and self.jrc.specified() and not self.jrc.handle():
                logger.error("Java redis client not available! Exiting.")
                exit(1)

            if self.jvrc and self.jvrc.specified() and not self.jvrc.handle():
                logger.error("Java version redis client not available! Exiting.")
                exit(1)

            if self.rrc and self.rrc.specified() and not self.rrc.handle():
                logger.error("Result redis client not available! Exiting.")
                exit(1)

        # check for configured oss database
        oss_db = config.get("OSS_DB", "Infrastructure")
        if not oss_db:
            logger.error("OSS_DB missing from config! Ignoring!")
        elif oss_db != "PostgreSQL":
            logger.error("Unsupported OSS_DB type: %s! Exiting", oss_db)
            exit(1)
        else:
            # check if postgresql if working
            try:
                import postgresql
                self.ndb = self.jdb = None
                if mode in ("Indexing", "Searching", "Signature", "Dumping"):
                    self.ndb = postgresql.PostgreSQL(config, "NATIVE", logger)
                elif mode in ("JavaSearching", "JavaIndexing", "JavaSignature"):
                    self.jdb = postgresql.PostgreSQL(config, "JAVA", logger)
                elif mode in ("Celery", "ApkSearching"):
                    self.ndb = postgresql.PostgreSQL(config, "NATIVE", logger)
                    self.jdb = postgresql.PostgreSQL(config, "JAVA", logger)
                else:
                    raise Exception("Invalid mode: " + mode)
            except Exception as e:
                logger.error("Error setting up postgresql: %s, Ignoring!", str(e))

        ###########################################################
        # Repos
        ###########################################################
        repo_src = config.get("REPO_SOURCE", "Infrastructure")
        if repo_src:

            # check against supported OSS
            repo_url_proto = config.get("REPO_URL_PROTOCOL", repo_src)
            repo_url_hostname = config.get("REPO_URL_HOSTNAME", repo_src)
            if repo_url_proto and repo_url_hostname:
                self.REPO_SOURCE = repo_src
                self.REPO_URL_PROTOCOL = repo_url_proto
                self.REPO_URL_HOSTNAME = repo_url_hostname
            else:
                logger.error("REPO_URL_PROTOCOL or REPO_URL_HOSTNAME (" + repo_src + ") missing from config")
                exit(1)

            # check if username/password supplied
            repo_credentials_file = config.get("REPO_CREDENTIALS_FILE", repo_src)
            if repo_credentials_file:
                self.REPO_CREDENTIALS_FILE = repo_credentials_file
                try:
                    with open(repo_credentials_file) as data_file:
                        self.REPO_CREDENTIALS = json.load(data_file)
                except Exception as jre:
                    logger.warn("Failed to read credentials file %s for %s. Will clone repos without credentials: %s!",
                                repo_credentials_file, repo_url_hostname, str(jre))
            else:
                logger.warn("No credentials for %s supplied. Will clone repos without credentials!", repo_url_hostname)

            # repo timeouts and retries
            val = config.get("REPO_CLONE_RETRIES", repo_src)
            if val:
                self.REPO_CLONE_RETRIES = int(val)

            val = config.get("REPO_CLONE_TIMEOUT", repo_src)
            if val:
                self.REPO_CLONE_TIMEOUT = int(val)

            val = config.get("REPO_SUBMODULE_TIMEOUT", repo_src)
            if val:
                self.REPO_SUBMODULE_TIMEOUT = int(val)

            val = config.get("INDEX_REPO_VERSIONS", mode)
            if val:
                self.INDEX_REPO_VERSIONS = self.str2bool(val)
                logger.info("INDEX_REPO_VERSIONS: %s", self.INDEX_REPO_VERSIONS)

            val = config.get("INDEX_SUBMODULES", mode)
            if val:
                self.INDEX_SUBMODULES = self.str2bool(val)
                logger.info("INDEX_SUBMODULES: %s", self.INDEX_SUBMODULES)

            val = config.get("INDEX_MAJOR_VERSIONS", mode)
            self.INDEX_MAJOR_VERSIONS = self.str2bool(val) if val else False
            if val:
                logger.info("INDEX_MAJOR_VERSIONS: %s", self.INDEX_MAJOR_VERSIONS)

            # max versions
            val = config.get("MAX_REPO_VERSIONS", mode)
            if val:
                self.MAX_REPO_VERSIONS = int(val)

            val = config.get("MIN_REPO_VERSIONS_DISTANCE", mode)
            if val:
                self.MIN_REPO_VERSIONS_DISTANCE = int(val)

            # configure/lexer config
            val = config.get("CONFIGURE_TIMEOUT", mode)
            self.CONFIGURE_TIMEOUT = int(val) if val else -1
            if val:
                logger.info("CONFIGURE_TIMEOUT: %s", self.CONFIGURE_TIMEOUT)
            val = config.get("LEXER_TIMEOUT", mode)
            self.LEXER_TIMEOUT = int(val) if val else -1
            if val:
                logger.info("LEXER_TIMEOUT: %s", self.LEXER_TIMEOUT)

            # license info
            val = config.get("SCAN_FILES_FOR_LICENSE", mode)
            if val:
                self.SCAN_FILES_FOR_LICENSE = self.str2bool(val)
                logger.info("SCAN_FILES_FOR_LICENSE: %s", self.SCAN_FILES_FOR_LICENSE)

            # github
            import github
            self.Github = github.Github(self)

            val = config.get("MAX_REPO_TAGS_QUERY", mode)
            if val:
                self.MAX_REPO_TAGS_QUERY = int(val)

        else:
            logger.error("No REPO_SOURCE found in config")
            exit(1)

        ###########################################################
        # Profiling config
        ###########################################################
        val = config.get("PROFILING_ENABLED", "Profiling")
        if val:
            self.PROFILING_ENABLED = self.str2bool(val)
            if self.PROFILING_ENABLED:
                self.profiler = cProfile.Profile()
            else:
                self.profiler = None

            if self.profiler:
                val = config.get("PROFILE_DUMP_FILE_PREFIX", "Profiling")
                if val:
                    self.PROFILE_DUMP_FILE_PREFIX =  val
                else:
                    self.PROFILE_DUMP_FILE_PREFIX = ''

        ###########################################################
        # Algorithm config
        ###########################################################
        val = config.get("TEST_MODE", "Algorithm")
        if val:
            self.TEST_REPO = self.str2bool(val)
            self.TEST_LIB = self.str2bool(val)

        val = config.get("MIN_STRING_LEN", "Algorithm")
        if val:
            self.MIN_STRING_LEN = int(val)

        val = config.get("MIN_SIZE_C_CPP_FILES", "Algorithm")
        if val:
            self.MIN_SIZE_C_CPP_FILES = int(val)

        val = config.get("MAX_SIZE_C_CPP_FILES", "Algorithm")
        if val:
            self.MAX_SIZE_C_CPP_FILES = int(val)

        val = config.get("MIN_PERCENT_MATCH", "Algorithm")
        if val:
            self.MIN_PERCENT_MATCH = literal_eval(val)

        val = config.get("MAX_NAME_DISTANCE", "Algorithm")
        if val:
            self.MAX_NAME_DISTANCE = float(val)

        val = config.get("USE_MD5_64BITS", "Algorithm")
        if val:
            self.USE_MD5_64BITS = self.str2bool(val)

        val = config.get("USE_MD5_INT", "Algorithm")
        if val:
            self.USE_MD5_INT = self.str2bool(val)

        val = config.get("USE_SHORT_STRS_AS_KEYS", "Algorithm")
        if val:
            self.USE_SHORT_STRS_AS_KEYS = int(val)

        val = config.get("USE_PERMISSION_STRINGS", "Algorithm")
        if val:
            self.USE_PERMISSION_STRINGS = self.str2bool(val)

        val = config.get("MAX_PER_STR_MATCHING_REPO_COUNT", "Algorithm")
        if val:
            self.MAX_PER_STR_MATCHING_REPO_COUNT = int(val)

        val = config.get("USE_UNIQ_FEATURES_FOR_TF", "Algorithm")
        if val:
            self.USE_UNIQ_FEATURES_FOR_TF = self.str2bool(val)

        val = config.get("USE_IFDEF_GROUP", "Algorithm")
        if val:
            self.USE_IFDEF_GROUP = self.str2bool(val)

        val = config.get("SIMHASH_DISTANCE", "Algorithm")
        if val:
            self.SIMHASH_DISTANCE = int(val)

        val = config.get("SEARCH_SIMHASH_DISTANCE", "Algorithm")
        self.SEARCH_SIMHASH_DISTANCE = int(val) if val else None

        val = config.get("SEARCH_REFCNT_PROPAGATION", "Algorithm")
        self.SEARCH_REFCNT_PROPAGATION = self.str2bool(val) if val else False

        val = config.get('USE_REDIS_PIPELINE', "Algorithm")
        self.USE_REDIS_PIPELINE = self.str2bool(val) if val else False

        val = config.get('SHUFFLE_INPUT', "Algorithm")
        self.SHUFFLE_INPUT = self.str2bool(val) if val else False

        val = config.get("USE_GROUPED_RESULT", "Algorithm")
        self.USE_GROUPED_RESULT = self.str2bool(val) if val else False

        val = config.get("MAX_GROUPED_RESULT_SIMHASH_DISTANCE", "Algorithm")
        if val:
            self.MAX_GROUPED_RESULT_SIMHASH_DISTANCE = int(val)

        val = config.get("USE_GROUPED_MATCH", "Algorithm")
        self.USE_GROUPED_MATCH = self.str2bool(val) if val else False

        val = config.get("GROUPED_NODE_TYPES", "Algorithm")
        self.GROUPED_NODE_TYPES = literal_eval(val) if val else ["dir"]

        val = config.get("MIN_GROUPED_FUNCFREQ", "Algorithm")
        self.MIN_GROUPED_FUNCFREQ = float(val) if val else 0

        val = config.get("MIN_GROUPED_PERCENT_MATCH", "Algorithm")
        self.MIN_GROUPED_PERCENT_MATCH = float(val) if val else 0.1

        val = config.get("MAX_GROUPED_REFCNT_RATIO", "Algorithm")
        self.MAX_GROUPED_REFCNT_RATIO = float(val) if val else 3

        val = config.get("MIN_MATCHING_SCORE", "Algorithm")
        if val:
            self.MIN_MATCHING_SCORE = literal_eval(val)

        val = config.get("MIN_LOW_LEVEL_MATCHING_SCORE", "Algorithm")
        self.MIN_LOW_LEVEL_MATCHING_SCORE = literal_eval(val) if val else self.MIN_MATCHING_SCORE

        val = config.get("MIN_MATCHING_REPO_FEATURE_COUNT", "Algorithm")
        if val:
            self.MIN_MATCHING_REPO_FEATURE_COUNT = float(val)

        val = config.get("NODE_ID_ALGORITHM", "Algorithm")
        if not val:
            self.NODE_ID_ALGORITHM = 'simhash'
        else:
            if val.lower() == 'md5':
                self.NODE_ID_ALGORITHM = 'md5'
            elif val.lower() == 'sha1':
                self.NODE_ID_ALGORITHM = 'sha1'
            elif val.lower() == 'simhash':
                self.NODE_ID_ALGORITHM = 'simhash'
            else:
                logger.error("Unsupported NODE_ID_ALGORITHM: %s, exiting!", self.NODE_ID_ALGORITHM)
                exit(1)

        val = config.get("MAX_METHOD_DIFFERENCE_DEGREE", "Algorithm")
        if val:
            self.MAX_METHOD_DIFFERENCE_DEGREE = float(val)
        val = config.get("USE_CENTROID_BIN", "Algorithm")
        if val:
            self.USE_CENTROID_BIN = self.str2bool(val)
        else:
            self.USE_CENTROID_BIN = False
        val = config.get("USE_ONE_CENTROID_BIN_IN_INDEX", "Algorithm")
        if val:
            self.USE_ONE_CENTROID_BIN_IN_INDEX = self.str2bool(val)
        else:
            self.USE_ONE_CENTROID_BIN_IN_INDEX = False
        val = config.get("MAX_CENTROID_RESULT_COUNT", "Algorithm")
        if val:
            self.MAX_CENTROID_RESULT_COUNT = int(val)
        else:
            self.MAX_CENTROID_RESULT_COUNT = -1

        val = config.get("USE_VERSION_DIFFERENCES", "Algorithm")
        self.USE_VERSION_DIFFERENCES = self.str2bool(val) if val else False
        if self.USE_VERSION_DIFFERENCES:
            val = config.get("USE_VERSION_AS_FEATURE", "Algorithm")
            self.USE_VERSION_AS_FEATURE = self.str2bool(val) if val else False
            val = config.get("MIN_VERSION_PERCENT_MATCH", "Algorithm")
            if val:
                self.MIN_VERSION_PERCENT_MATCH = float(val)

        ###########################################################
        # Mode specific configuration, Java indexing and searching config, or Celery worker
        ###########################################################
        # for signature generation and loading
        binary_sig = config.get("BINARY_SIG", mode)
        self.binary_sig = True if binary_sig and self.str2bool(binary_sig) else False
        keep_sig = config.get("KEEP_SIG", mode)
        self.keep_sig = True if keep_sig and self.str2bool(keep_sig) else False
        self.repo_sig_dir = config.get("REPO_SIG_DIR", mode)
        if not self.repo_sig_dir:
            logger.info("No REPO_SIG_DIR found for '%s' in config, Ignoring", mode)
        self.java_sig_dir = config.get("JAVA_SIG_DIR", mode)
        if not self.java_sig_dir:
            logger.info("No JAVA_SIG_DIR found for '%s' in config, Ignoring", mode)
        self.java_sig_load_dirs = config.get("JAVA_SIG_LOAD_DIRS", mode)
        if not self.java_sig_load_dirs:
            logger.info("No JAVA_SIG_LOAD_DIRS found for '%s' in config, Ignoring", mode)
        else:
            self.java_sig_load_dirs = literal_eval(self.java_sig_load_dirs)
        self.comp_sig_load_dirs = config.get("COMP_SIG_LOAD_DIRS", mode)
        if not self.comp_sig_load_dirs:
            logger.info("No COMP_SIG_LOAD_DIRS found for '%s' in config, Ignoring", mode)
        else:
            self.comp_sig_load_dirs = literal_eval(self.comp_sig_load_dirs)
        # If keep_sig is True, then optional compress sig to save space!
        compress_sig = config.get("COMPRESS_SIG", mode)
        self.compress_sig = True if compress_sig and self.str2bool(compress_sig) else False
        reuse_sig = config.get("REUSE_SIG", mode)
        self.reuse_sig = True if reuse_sig and self.str2bool(reuse_sig) else False
        skip_no_sig = config.get("SKIP_NO_SIG", mode)
        self.skip_no_sig = True if skip_no_sig and self.str2bool(skip_no_sig) else False

        # for searching configurations
        search_features = config.get("SEARCH_FEATURES", mode)
        if mode == 'Searching':
            default_features = ['str', 'func', 'funcname']
        else:
            default_features = ['strings', 'centroids']
        self.search_features = literal_eval(search_features) if search_features else default_features

        # for feature counting
        feature_key_type = config.get("FEATURE_KEY_TYPE", mode)
        self.feature_key_type = feature_key_type if feature_key_type else 'hset'
        common_feature_file = config.get("COMMON_FEATURE_FILE", mode)
        self.common_feature_file = common_feature_file if common_feature_file else None

        # for validate
        self.app_pb_load_dirs = config.get("APP_PB_LOAD_DIRS", mode)
        if self.app_pb_load_dirs:
            self.app_pb_load_dirs = literal_eval(self.app_pb_load_dirs)
        ignore_developer_website = config.get("IGNORE_DEVELOPER_WEBSITE", mode)
        self.ignore_developer_website = True if ignore_developer_website and self.str2bool(ignore_developer_website) else False

        # for all modes
        ignore_scanned = config.get("IGNORE_SCANNED", mode)
        self.ignore_scanned = True if ignore_scanned and self.str2bool(ignore_scanned) else False
        self.exclude_file = config.get("EXCLUDE_FILE", mode)
        self.failure_file = config.get("FAILURE_FILE", mode)
        self.RESULT_DIR = config.get("RESULT_DIR", mode)

        ###########################################################
        # Check if requested to log stats
        ###########################################################
        stats_logger = None
        val = config.get("STATS", mode)
        if val and self.str2bool(val):
            try:
                # stats logger
                logfile_prefix = config.get("STATS_LOGFILE_PREFIX", mode)
                self.stats_logfile_prefix = logfile_prefix
                if logfile_prefix:
                    stats_logger = applogger.Logger("Stats", logfile_prefix).get()
                else:
                    raise Exception("No STATS_LOGFILE_PREFIX found for '%s' in config", mode)
            except Exception as e:
                logger.error("Error setting stats logger: %s! Continuing without it.", str(e))

        self.stats_logger = stats_logger

        ###########################################################
        # Check for parallelism
        ###########################################################

        # look for 'queuing' in config
        queuing = config.get("QUEUING", "Infrastructure")
        if not queuing:
            self.QUEUING = None
            logger.warn("Non-parallel instance. May be slow!")
            return
        elif queuing == "Celery":
            self.QUEUING = queuing
            logger.info("Celery based parallel instance. Should be fast!")
        else:
            logger.error("Unsupported queuing protocol: %s", queuing)
            exit(1)

        # get broker url and backend config
        val = config.get("CELERY_BROKER_URL", "Celery")

        if val:
            self.CELERY_BROKER_URL = val.strip()
        else:
            self.CELERY_BROKER_URL = 'amqp://'

        val = config.get("CELERY_RESULTS_BACKEND", "Celery")
        if val:
            self.CELERY_RESULTS_BACKEND = val.strip()
        else:
            self.CELERY_RESULTS_BACKEND = 'rpc://'

        # if already a worker
        if mode == "Celery" or mode == "Dumping":
            return

        # check if celery workers are running
        try:
            celery_check(self)
        except Exception as e:
            logger.error("%s", str(e))
            exit(1)

    def str2bool(self, v):
        return v.lower() in ("yes", "true", "t", "1", "enabled")

###########################################################
# Main
###########################################################
if __name__ == '__main__':
    # parse args
    import sys
    import options

    argv = sys.argv[1:]
    opts = options.Options(argv)
    if not opts:
        exit(1)

    # get args
    mode, args = opts.argv()

    # create detector
    detector = Detector(mode=mode)
    if not detector:
        exit(1)

    if mode == "Searching":
        import searching

        searching.run(detector, args)
    elif mode == "Indexing":
        import indexing

        indexing.run(detector, args)
    elif mode == "Signature":
        import signature

        signature.run(detector, args)
    elif mode == "Dumping":
        import stats

        stats.run(detector, args)
    elif mode == "FeatureCounting":
        import feature_count

        feature_count.run_counter(detector, args)
    elif mode == 'JavaSearching':
        import searching_java

        searching_java.run_searcher(detector, args)
    elif mode == 'JavaIndexing':
        import indexing_java

        indexing_java.run_indexer(detector, args)
    elif mode == 'JavaSignature':
        import signature_java

        signature_java.run_signature(detector, args)
    elif mode == 'ApkSearching':
        import searching_apk

        searching_apk.run_searcher(detector, args)
    elif mode == 'ApkExtract':
        import extract_apk

        extract_apk.run_extractor(detector, args)
    elif mode == 'Validate':
        import validate

        validate.run_validator(detector, args)
    else:
        print "Invalid command " + mode
