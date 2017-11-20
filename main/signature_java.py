import collections
import csv
import logging
import os
import shutil
import sys
import time
import zipfile
import magic
from collections import Counter
from os.path import join, basename, abspath, exists, splitext, dirname
from subprocess import call, Popen, PIPE

import logger as applogger
import utils
from utils import repo_scanned, any_and_return
from centroid import get_typed_centroid_key, get_centroid_string
from compress_files import get_compressed_file
from job_util import read_proto_from_file, read_proto_from_string, list_recursive
from signature_java_constants import (DEVNULL, PUBLIC, SIG_SUFFIX, SIG_ZIP_SUFFIX, ZIP_SUFFIX, JAR_SUFFIX,
                                      CLASSES_JAR, JOB_CHUNK, JAVA_SUFFIXES)
from signature_java_constants import primitive_types, object_methods, framework_prefix

# Resolve dependencies
try:
    # java_parser
    if not exists('java_parser'):
        JAVA_PARSER_DIR = None
        JAVA_PARSER_JAR = None
        ANDROID_JAR_DIR = None
        raise Exception("java_parser does not exist!")
    else:
        JAVA_PARSER_DIR = 'java_parser'
        JAVA_PARSER_JAR = 'class-signature.jar'
        ANDROID_JAR_DIR = abspath(join(JAVA_PARSER_DIR, 'platforms'))
    sys.path.append('java_parser/src/gtisc/gpl_violation/proto')
    import class_sig_pb2
    p = Popen(['java', '-version'], stdout=PIPE, stderr=PIPE)
    version_output, version_error = p.communicate()
    debian_help_link = "http://tecadmin.net/install-java-8-on-debian/"
    if not ((version_output and '1.8' in version_output) or (version_error and '1.8' in version_error)):
        raise Exception("Incorrect java version: (out: %s, error: %s), refer to %s for installing java 8 on debian"
                        % (version_output, version_error, debian_help_link))
except Exception as e:
    logging.error("Error checking java_parser content! Error: %s", str(e))


###########################################################
# init state
###########################################################
logger = None
stats_logger = None
dump_logger = None


def read(fname, mode='rb'):
    with open(fname, mode) as f:
        return f.read()


def get_input_id(input_path):
    return 'repo-' + utils.md5_digest_str(input_path)


###########################################################
# convert aar format to jar format
###########################################################
def get_mime_for_file(filepath):
    return magic.from_file(filepath, mime=True)

def zip_and_remove(filepath):
    # zip -j filepath.zip filepath && rm filepath
    zf = zipfile.ZipFile(filepath + ZIP_SUFFIX, mode='w', compression=zipfile.ZIP_DEFLATED)
    try:
        # Use a separate process to do zip
        # call(['zip', '-j', filepath + ZIP_SUFFIX, filepath])
        # Use zipfile to create and write zipfile
        zf.write(filepath, arcname=basename(filepath))
        os.remove(filepath)
    except Exception as e:
        logger.error("Error zip_and_remove processing %s", filepath)
    finally:
        zf.close()
    return filepath + ZIP_SUFFIX

def read_from_zipfile(zip_filepath, filename):
    file_with_meta = get_compressed_file(zip_filepath)
    file_obj = file_with_meta.accessor
    return file_obj.read(filename)

def aar2jar(aar_path):
    content = read_from_zipfile(zip_filepath=aar_path, filename=CLASSES_JAR)
    expected_jar_path = splitext(aar_path)[0] + JAR_SUFFIX
    outf = open(expected_jar_path, 'w')
    outf.write(content)
    outf.close()
    return expected_jar_path


###########################################################
# common utilities for indexing_java and searching_java
###########################################################
def get_no_package_func(method_proto, non_application_classes):
    # Remove the package, but keep the class name!
    normed_arg_types = []
    for arg_type in method_proto.paramter_types:
        if arg_type not in non_application_classes:
            normed_arg_types.append(arg_type.split('.')[-1])
        else:
            normed_arg_types.append(arg_type)
    normed_return_type = method_proto.return_type.split('.')[-1] if method_proto.return_type not in non_application_classes else method_proto.return_type
    funcname = "%s %s.%s(%s)" % (normed_return_type, method_proto.class_name.split('.')[-1], method_proto.method_name, ",".join(normed_arg_types))
    return funcname

def get_obfuscation_resilient_func(method_proto, non_application_classes):
    # norm func id, is just to normalize the user defined types, and ignore function names
    normed_arg_types = []
    for arg_type in method_proto.paramter_types:
        if arg_type in primitive_types or arg_type in non_application_classes:
            normed_arg_types.append(arg_type)
        else:
            normed_arg_types.append("APP_CLASS")
    if method_proto.return_type in primitive_types or method_proto.return_type in non_application_classes:
        normed_return_type = method_proto.return_type
    else:
        normed_return_type = "APP_CLASS"
    normed_method_name = "APP_METHOD" if method_proto.method_name not in object_methods else method_proto.method_name

    # prepend a "norm:" in the beginning to differentiate this method name from original one
    return "norm:" + normed_return_type + " " + normed_method_name + "(" + ",".join(normed_arg_types) + ")"

def get_class_string(normfuncs, unique=False):
    """
    Get the normalized class string.
    :param normfuncs: list or dict of normalized functions for one class
    :param unique: bool, use unique normalized func name or not
    :return: str, normalized class string
    """

    normfunc_str = ''
    if isinstance(normfuncs, dict):
        # If the input is dict of normalized function names along with their frequency (e.g. in indexing)
        normfunc_list = sorted(normfuncs.keys())
        for key in normfunc_list:
            if unique:
                normfunc_str += key + ','
            else:
                normfunc_str += ','.join([key] * normfuncs[key]) + ','

    elif isinstance(normfuncs, list):
        # If the input is list of normalized function names (e.g. in searching)
        normfunc_list = sorted(normfuncs)
        if unique:
            normfunc_set = set()
            for key in normfunc_list:
                if key not in normfunc_set:
                    normfunc_str += key + ','
        else:
            normfunc_str = ','.join(normfunc_list) + ','

    else:
        logger.error("Unexpected input type for get_normclass: type %s, value %s", type(normfuncs), normfuncs)

    return normfunc_str

###########################################################
# signature
###########################################################
def signature(input_path, outdir, input_type='jar', binary=True, xmx='16G', thread_num=8,
              compress_sig=False, failure_file=None):

    # Call the java processing app
    logging.info("processing %s" % input_path)
    input_path = abspath(input_path)
    outdir = abspath(outdir)
    cwd = os.getcwd()
    os.chdir(JARSIGNIFY_DIR)
    acs = class_sig_pb2.AllClassesSummary()

    try:
        # If the input is android archive library (aar), then extract it to jar first, and then call the signature process
        # Note: the output file name should be changed from "jar.sig" to "aar.sig"
        is_aar_format = False
        if input_path.endswith('.aar'):
            is_aar_format = True
            if compress_sig:
                outfile = join(outdir, basename(input_path) + SIG_ZIP_SUFFIX)
            else:
                outfile = join(outdir, basename(input_path) + SIG_SUFFIX)
            expected_tmp_outfilename = basename(input_path) + SIG_SUFFIX
            input_path = aar2jar(aar_path=input_path)

        # output signature file to tmp folder, to speed up program
        tmp_outdir = '/tmp/'

        # call the java signature on input file
        cmds = ['java', '-Xmx%s' % xmx, '-jar', JARSIGNIFY_JAR, '-inputType', input_type.upper(), '-inputPath', input_path,
                '-androidJarDir', ANDROID_JAR_DIR, '-resultDir', tmp_outdir, '-threadNum', str(thread_num)]
        if binary:
            cmds += ['-binaryOutput']
        logging.debug("Running command: '%s'" % ' '.join(cmds))
        ret = call(cmds, stdout=DEVNULL, stderr=DEVNULL)
        # rec = call(cmds)  # if debugging
        if ret == 1:
            logging.error("processing %s failed" % input_path)

        # output signature file to tmp folder, to speed up program
        tmp_outfile = join(tmp_outdir, basename(input_path) + SIG_SUFFIX)
        read_proto_from_file(proto=acs, filename=tmp_outfile, binary=binary)

        # if input is aar format, remove temporary jar file, rename output file to the expected outfile, so that we can reuse it!
        if is_aar_format:
            # outfile: already specified in previous sections
            os.remove(input_path)
            shutil.move(tmp_outfile, join(dirname(tmp_outfile), expected_tmp_outfilename))
            tmp_outfile = join(dirname(tmp_outfile), expected_tmp_outfilename)
        else:
            if compress_sig:
                outfile = join(outdir, basename(input_path) + SIG_ZIP_SUFFIX)
            else:
                outfile = join(outdir, basename(input_path) + SIG_SUFFIX)

        # if compress signature, then zip it and remove the resulting signature file.
        if compress_sig:
            tmp_outfile = zip_and_remove(tmp_outfile)
        shutil.move(tmp_outfile, outfile)

    except Exception as e:
        logging.error("Error when extracting signature for %s: %s", input_path, str(e))
        if failure_file:
            open(failure_file, 'a').write(input_path + '\n')
    finally:
        os.chdir(cwd)
    return acs


def get_all_classes_summary(input_path, outdir, input_type='jar', main=None):
    """
    Get the summary of all classes in input_path

    :param input_path: path to input
    :param outdir: the directory containing the output
    :param input_type: type of input
    :param main: the detector module, which contains the following parameters
        binary: output as binary or not
        reuse_sig: reuse generated signature or not
        failure_file: the failure file
        java_sig_load_dirs: the path to sig reuse directories
    :return: proto, AllClassesSummary
    """
    start_summary_time = time.time()
    if main:
        binary = main.binary_sig
        reuse_sig = main.reuse_sig
        compress_sig = main.compress_sig
        skip_no_sig = main.skip_no_sig
        failure_file = main.failure_file
    else:
        binary = True
        reuse_sig = False
        compress_sig = False
        skip_no_sig = False
        failure_file = None

    # compute the expected output filename
    expected_outname = None
    expected_outname_exists = False
    if reuse_sig:
        if main.java_sig_load_dirs:
            for d in main.java_sig_load_dirs:
                if compress_sig:
                    expected_outname = join(d, basename(input_path) + SIG_ZIP_SUFFIX)
                else:
                    expected_outname = join(d, basename(input_path) + SIG_SUFFIX)
                if os.path.exists(expected_outname):
                    expected_outname_exists = True
                    break
        else:
            if compress_sig:
                expected_outname = join(outdir, basename(input_path) + SIG_ZIP_SUFFIX)
            else:
                expected_outname = join(outdir, basename(input_path) + SIG_SUFFIX)
            expected_outname_exists = True if os.path.exists(expected_outname) else False

    if reuse_sig and expected_outname_exists:
        # Reusing previously generated signature results
        logger.info("reusing previous generated signature file %s for %s", expected_outname, input_path)
        acs = class_sig_pb2.AllClassesSummary()
        if compress_sig:
            content_string = read_from_zipfile(expected_outname, splitext(basename(expected_outname))[0])
            read_proto_from_string(proto=acs, content_string=content_string, binary=binary)
        else:
            read_proto_from_file(proto=acs, filename=expected_outname, binary=binary)
    elif skip_no_sig:
        logger.info("skipping %s, because it doesn't have the previous generated signature file %s!",
                    input_path, expected_outname)
        acs = class_sig_pb2.AllClassesSummary()
    else:
        # Generate signature for the current input file
        acs = signature(input_path=input_path, outdir=outdir, input_type=input_type, binary=binary,
                        compress_sig=compress_sig, failure_file=failure_file)

    # Log time if requested
    if stats_logger:
        stats_logger.info("time elapsed for getting summary for %s is %0.2f seconds",
                          input_path, time.time() - start_summary_time)

    # If we choose to TEST_REPO and dump the strings etc.
    if main and main.TEST_REPO:
        # initialize the dump logger
        global dump_logger
        logfilepath = '/tmp/java_signature'
        logfilepath += '_dump_' + basename(input_path).replace('/', '_') + '.csv'
        dump_logger = applogger.Logger("Dump", logfilepath).get()

        # get the data
        summary_proto = acs

        # get the non application class set
        used_non_application_class_set = set()
        for class_pair in summary_proto.class_pairs:
            if (not class_pair.classname2_is_application_class) and (class_pair.classname2.startswith(framework_prefix)):
                used_non_application_class_set.add(class_pair.classname2)

        # get the list of strs, funcs, normclasses and centroids
        strs_to_search = []
        classes_to_search = []
        normclasses_to_search = []
        centroids_to_search = []
        for class_proto in summary_proto.classes:
            string_const = []
            function_name = []
            normfunction_name = []
            centroids_str = []
            for method_proto in class_proto.methods:
                for string in method_proto.string_constants:
                    strs_to_search.append("strings-" + string)
                    # stats
                    string_const.append(string)
                centroids_to_search.append(get_typed_centroid_key(main=main, centroid=method_proto.centroid,
                                                                  centroidinvoke=method_proto.centroid_with_invoke))

                # stats
                function_name.append(get_no_package_func(
                    method_proto=method_proto, non_application_classes=used_non_application_class_set))
                # stats
                normfunction_name.append(get_obfuscation_resilient_func(
                    method_proto=method_proto, non_application_classes=used_non_application_class_set))
                # stats
                centroids_str.append(get_centroid_string(centroid=method_proto.centroid,
                                                         centroidinvoke=method_proto.centroid_with_invoke))

            classes_to_search.append("classes-" + get_class_string(function_name, unique=False))
            normclasses_to_search.append("normclasses-" + get_class_string(normfunction_name, unique=False))

            if stats_logger:
                # permission is hard to get, ignoring now!
                stats_logger.info("class %s -->\nstring constants (%d): %s\nmethod names (%d): %s\nnorm method names (%d): %s\ncentroids (%d): %s",
                                  class_proto.class_name, len(string_const), string_const,
                                  len(function_name), function_name, len(normfunction_name), normfunction_name,
                                  len(centroids_str), centroids_str)

        str_features_map = {k: v for k, v in Counter(strs_to_search).items()}
        class_features_map = {k: v for k, v in Counter(classes_to_search).items()}
        normclass_features_map = {k: v for k, v in Counter(normclasses_to_search).items()}
        centroid_features_map = {k: v for k, v in Counter(centroids_to_search).items()}
        final_map = {}
        final_map.update(str_features_map)
        final_map.update(class_features_map)
        final_map.update(normclass_features_map)
        final_map.update(centroid_features_map)

        path = dump_logger.handlers[1].baseFilename
        logger.info("Dumping strings/functions/norm functions to %s", path)
        fieldnames = ['type', 'freq', 'feature', 'feature_key']
        import unicodecsv
        writer = unicodecsv.DictWriter(open(path, 'w'), fieldnames=fieldnames)
        writer.writeheader()
        for typed_feat, freq in sorted(final_map.items(), key=lambda item: item[0]):
            t, feat = typed_feat.split('-', 1)
            writer.writerow({'type': t, 'freq': freq, 'feature': feat,
                             'feature_key': '%s-%s' % (t, str(utils.get_key(main, feat)))})

    return acs


def get_all_classes_summary_dict(input_path, outdir, input_type='jar', main=None):
    """
    :return: summary dict, with keys 'string_constants', 'is_public', 'permission_strings', 'public_methods'
    """
    acs = get_all_classes_summary(input_path=input_path, outdir=outdir, input_type=input_type, main=main)
    class_summary_dict = {}
    for c in acs.classes:
        class_summary_dict.setdefault(c.class_name, {})
        # string_constants, pub methods
        for m in c.methods:
            if len(m.string_constants) > 0:
                str_set = class_summary_dict[c.class_name].setdefault('string_constants', set())
                str_set |= set(m.string_constants)
            if PUBLIC in m.modifiers:
                class_summary_dict[c.class_name].setdefault('public_methods', set()).add(m.method_subsignature)
        # pub classes
        if PUBLIC in c.modifiers:
            class_summary_dict[c.class_name].setdefault('is_public', True)
        # permissions
        if len(c.permission_strings) > 0:
            perm_set = class_summary_dict[c.class_name].setdefault('permission_strings', set())
            perm_set |= set(c.permission_strings)
    return class_summary_dict


###########################################################
# Repo filter
###########################################################
def get_input_list(main, redis, redis_pipe, input_path, input_type=None, path_as_id=False,
                   skip_scanned=False, skip_signatured=False, skip_failure=False):
    """
    Get the list of input from input path and input type. Redis is used to filter out processed inputs.
    If input type is csv, this file expects the input column to be name input_path.

    :param main: the detector main module
    :param redis: connection to redis db (the result db)
    :param input_path: path to the input
    :param input_type: type of input
    :param skip_scanned: skip scanned or not
    :param skip_signatured: skip signatured or not, only useful for java_signature job
    :param skip_failure: skip the failure input files
    :return: list of input paths
    """
    input_list = []
    input_path = abspath(input_path)
    if os.path.isfile(input_path):
        if input_path.endswith(JAVA_SUFFIXES):
            input_list.append(abspath(input_path))
        elif input_path.endswith(('csv',)):
            reader = csv.DictReader(open(input_path, 'r'))
            input_field = any_and_return(['apk_path', 'path', 'app_path', 'input_path'], reader.fieldnames)
            if not input_field:
                raise Exception("cannot find input field in %s" % reader.fieldnames)
            for row in reader:
                input_list.append(row[input_field])
        else:
            raise Exception('Unhandled type of input')
    elif os.path.isdir(input_path):
        input_list = list_recursive(indir=input_path, suffix='.' + input_type)
    else:
        raise Exception("Unexpected type of input")

    if skip_scanned:
        # Skip scanned files
        if main.USE_REDIS_PIPELINE and redis_pipe is not None:
            tmpinput_list = []
            for item in input_list:
                tmpinput_list.append(item)
                redis_pipe.exists(item if path_as_id else get_input_id(item))
            tmpexists_list = redis_pipe.execute()
            input_list = [tmpinput for tmpinput, tmpexists in zip(tmpinput_list, tmpexists_list) if not tmpexists]
        else:
            input_list = [item for item in input_list if
                          not repo_scanned(redis=redis, repo_id=item if path_as_id else get_input_id(item))]
    if logger:
        logger.info("loaded %d input items to process!", len(input_list))
    else:
        print ("loaded %d input items to process!" % len(input_list))

    if skip_signatured:
        # Skip signatured files, used for java_signature job
        if not main.exclude_file:
            if logger:
                logger.info("exclude file is not specified")
        elif not exists(main.exclude_file):
            if logger:
                logger.info("exclude file doesn't exist")
        else:
            done_set = set([basename(fname) for fname in filter(bool, open(main.exclude_file, 'r').read().split('\n'))])
            if main.compress_sig:
                input_list = [item for item in input_list if (basename(item) + SIG_ZIP_SUFFIX not in done_set) and
                              (join(main.java_sig_dir, basename(item) + SIG_ZIP_SUFFIX) not in done_set)]
            else:
                input_list = [item for item in input_list if (basename(item) + SIG_SUFFIX not in done_set) and
                              (join(main.java_sig_dir, basename(item) + SIG_SUFFIX) not in done_set)]
        if logger:
            logger.info("after filtering using exclude file, there are %d input items to process!", len(input_list))
        else:
            print ("after filtering using exclude file, there are %d input items to process!" % len(input_list))

    if skip_failure:
        # Skip failure files, used for all jobs
        if not main.failure_file:
            if logger:
                logger.info("failure file is not specified")
        elif not exists(main.failure_file):
            if logger:
                logger.info("failure file doesn't exist")
        else:
            failure_set = set([basename(fname) for fname in filter(bool, open(main.failure_file, 'r').read().split('\n'))])
            if main.compress_sig:
                input_list = [item for item in input_list if (basename(item) + SIG_ZIP_SUFFIX not in failure_set) and
                              (join(main.java_sig_dir, basename(item) + SIG_ZIP_SUFFIX) not in failure_set)]
            else:
                input_list = [item for item in input_list if (basename(item) + SIG_SUFFIX not in failure_set) and
                              (join(main.java_sig_dir, basename(item) + SIG_SUFFIX) not in failure_set)]
        if logger:
            logger.info("after filtering using failure file, there are %d input items to process!", len(input_list))
        else:
            print ("after filtering using failure file, there are %d input items to process!" % len(input_list))

    if main.SHUFFLE_INPUT:
        import random
        random.shuffle(input_list)
    return input_list


def signature_classes(main, input_path, input_type):
    start = time.time()
    # global values
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger

    # main.keep_sig must be true, otherwise this is meaningless
    # assert main.keep_sig and main.java_sig_dir
    #
    # make directory if it doesn't exist
    if not os.path.exists(main.java_sig_dir):
        os.makedirs(main.java_sig_dir)
    summary_dict = get_all_classes_summary_dict(input_path=input_path, outdir=main.java_sig_dir, input_type=input_type, main=main)
    class_n = len(summary_dict); pub_class_n = 0; pub_method_n = 0; str_const_n = 0
    for classname, classattr in summary_dict.items():
        if 'is_public' in classattr and classattr['is_public']:
            pub_class_n += 1
        if 'public_methods' in classattr:
            pub_method_n += len(classattr['public_methods'])
        if 'string_constants' in classattr:
            str_const_n += len(classattr['string_constants'])
    # time logging
    end = time.time()
    if stats_logger:
        stats_logger.info("time elapsed for signaturing %s: %0.2f seconds", input_path, end-start)
        stats_logger.info("%s, class %d, pub_class %d, pub_method %d, str_const %d",
                          basename(input_path), class_n, pub_class_n, pub_method_n, str_const_n)


###########################################################
# Signature
###########################################################
def run_signature(main, argv):
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger

    # the outer args
    if len(argv) != 2:
        logger.error('expects two args')
        exit(1)
    if argv[0] == 'dump':
        main.TEST_REPO = True

    # the inner args
    argv = argv[1]
    if len(argv) < 1 or len(argv) > 2:
        logger.error('expects args: $input_path [$input_type] [-d]')
        exit(1)

    input_path = argv[0]
    input_type = argv[1] if len(argv) == 2 else 'jar'
    if not os.path.exists(input_path):
        logger.error('%s does not exist', input_path)
        exit(1)

    input_list = get_input_list(main=main, redis=None, redis_pipe=None, input_path=input_path, input_type=input_type,
                                path_as_id=True, skip_scanned=False, skip_signatured=True, skip_failure=True)
    print ("There are %d input to be signatured" % len(input_list))
    # start signature
    # query the database
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
            from celery_tasks import signature_java_worker

            # group jobs
            input_count = len(input_list)
            for index in range(0, input_count, JOB_CHUNK):
                tmp_input_list = input_list[index: min(index + JOB_CHUNK, input_count)]
                if index + JOB_CHUNK > input_count:
                    logger.info("Processing the %d %d input" % (index / JOB_CHUNK + 1, input_count - index))
                else:
                    logger.info("Processing the %d %d input" % (index / JOB_CHUNK + 1, JOB_CHUNK))
                job = group(signature_java_worker.s(item, input_type) for item in tmp_input_list)
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
                    pb.msg('Signaturing {0} '.format(item))

                # signature libs/apps
                signature_classes(main=main, input_path=item, input_type=input_type)

                # update progressbar
                count += 1
                pb.update(count)

            # all done
            if not signal.caught() and pb:
                pb.finish()

    else:
        logger.error("No lib(s) to signature")


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise Exception("python signature_java.py $input_type $input_file $outdir")
    input_type = sys.argv[1]
    input_path = sys.argv[2]
    outdir = sys.argv[3]
    print (get_all_classes_summary_dict(input_path=input_path, outdir=outdir, input_type=input_type))
