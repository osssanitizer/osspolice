import json
import os
import random
import re
import shutil
import stat
import sys
import logging
import tempfile
import time
import urlparse
from genericpath import exists
from subprocess32 import Popen, PIPE, TimeoutExpired
from itertools import chain

import utils
import proto.file_sig_pb2 as files_pb
from os.path import dirname, basename, join, splitext
from common import SrcExtensions, get_typed_key
from extract_apk import get_license_info_wrapper
from signature_java import read_from_zipfile, zip_and_remove
from signature_java_constants import DEVNULL, SIG_SUFFIX, SIG_ZIP_SUFFIX
from job_util import read_proto_from_file, read_proto_from_string, list_recursive, write_proto_to_file
from metric.levenshtein_wrapper import levenshtein

"""
There are four ways to include lexer/parser module. Adopting Option 4 now.

Option 1: LexerParserOutputWrapper uses Clang Lexer + Gtags Parser
e.g. from native_parser.LexerParserOutputWrapper import LexerParser
Option 2: LexerParserWrapper uses Clang Lexer + Parser, use subprocess to call into this, o.w. program may crash
e.g. from native_parser.LexerParserWrapper import LexerParser
# Option 3: LexerOutputWrapper uses Clang Lexer
from native_parser.LexerOutputWrapper import callLexerOutput
"""
# Option 4: call LexerParserWrapper using subprocess
from native_parser.LexerParserWrapper import FeatureFlags, FunctionType

LEXER_PARSER_PATH = 'native_parser/LexerParserWrapper.py'

###########################################################
# init state
###########################################################
logger = None
stats_logger = None
dump_logger = None
JOB_CHUNK = 50000
# Match the license filenames
license_pattern = re.compile(
    r"""\b(copying|license|licence|licensing|gnu|gpl|gplv2|gplv3|lgpl|lgplv2|lgplv3|agpl|agplv2|agplv3|apache|apl|bsd|cddl|mit|mozilla|mpl|mplv2|eclipse|epl|qpl|isc|readme)\b""",
    re.IGNORECASE)
independent_pattern = re.compile(
    r"""\b(changelog|autogen|configure|thanks|release-notes|ReleaseNotes|changes|whatsnew)\b""",
    re.IGNORECASE)
thirdparty_pattern = re.compile(r"""\b(3rdparty|3rd.party|thirdparty|third.party|external|externals)\b""",
                                re.IGNORECASE)
source_pattern = re.compile(r"""\b(src|source)\b""", re.IGNORECASE)
# Match the build related filenames
make_based_build_files_pattern = re.compile(r"""^(makefile$|config|autogen)""",
                                            re.IGNORECASE)
cmake_based_build_files_pattern = re.compile(r"""^CMakeLists.txt$""", re.IGNORECASE)


###########################################################
# Helper functions
###########################################################
def exec_command(cmd, args, cwd, timeout=None):
    """
    Executes shell command inside @repo_path
    returns exec code
    """
    pipe = None
    try:
        env = os.environ
        env["PATH"] = env["NDK_TOOLCHAIN"] + "/bin:" + env["PATH"]
        pipe = Popen(args, stdin=PIPE, stdout=PIPE, cwd=cwd, env=env)
        stdout, error = pipe.communicate(timeout=timeout) if (timeout and timeout > 0) else pipe.communicate()
        logger.debug("stdout: %s", stdout)
        return pipe.returncode

    except TimeoutExpired as te:
        pipe.terminate()
        logger.error("%s timed out: %s", cmd, str(te))
        return 0

    except Exception as e:
        logger.error("%s subprocess failed: %s", cmd, str(e))
        return -1


def is_src_file(filename, extensions=SrcExtensions, exclude_3rdparty=False, exclude_dirs=None):
    if exclude_3rdparty and re.search(thirdparty_pattern, dirname(filename)):
        return False
    if exclude_dirs and dirname(filename).startswith(tuple(exclude_dirs)):
        return False
    return any(filename.endswith(e) for e in extensions)


def is_license_file(filename):
    return True if license_pattern.search(basename(filename)) else False


def is_independent_file(filename):
    return True if independent_pattern.search(basename(filename)) else False


def is_ind_or_lic_file(filename):
    bfilename = basename(filename)
    return True if independent_pattern.search(bfilename) or license_pattern.search(bfilename) else False


def get_filtered_files(repo_path, filter_callback=None):
    """
    Get filtered files based on filter callback
    """
    try:
        for root, dirs, files in os.walk(repo_path):
            try:
                filepaths = [os.path.join(root, filename) for filename in files]
                if filter_callback:
                    filtered_filepaths = filter(filter_callback, filepaths)
                else:
                    filtered_filepaths = filepaths
                for filepath in filtered_filepaths:
                    try:
                        path = os.path.join(root, filepath)
                        if os.path.isfile(path) and not os.path.islink(path):
                            yield root, path

                    except Exception as e:
                        logger.error("Error retrieving source file in %s (root: %s, dirs: %s filename: %s): %s",
                                     repo_path, root, dirs, filepath, str(e))
                        continue

            except Exception as e:
                logger.error("Error retrieving source files in %s (root: %s, dirs: %s filename: %s): %s",
                             repo_path, root, dirs, files, str(e))
                continue

    except Exception as e:
        logger.error("Error retrieving source files in %s (root: %s, dirs: %s filename: %s): %s",
                     repo_path, root, dirs, files, str(e))


def get_src_files(repo_path, exclude_3rdparty=False, exclude_dirs=None):
    """
    Function to build a list of all files with an extension in @ext
    """
    if exclude_3rdparty or exclude_dirs:
        from functools import partial
        partial_is_src_file = partial(is_src_file, exclude_3rdparty=exclude_3rdparty, exclude_dirs=exclude_dirs)
        filtered_result = list(get_filtered_files(repo_path, filter_callback=partial_is_src_file))
        # if there are source files after exclusion, then return these files, o.w. return all source files
        if len(filtered_result) > 0:
            return filtered_result
    return get_filtered_files(repo_path, filter_callback=is_src_file)


def get_license_files(repo_path, get_thirdparty_file=False):
    """
    Function to build a list of license (third-party) files within the repository
    """
    if get_thirdparty_file:
        return get_filtered_files(repo_path, filter_callback=is_ind_or_lic_file)
    else:
        return get_filtered_files(repo_path, filter_callback=is_license_file)


###########################################################
# Use lexer and parser to extract strings/functions
###########################################################
def callLexerParserSubprocess(arg, rootdir, mode=1, flags=FeatureFlags.NONE, timeout=None, log_std=False, tag=None,
                              exclude_3rdparty=False, exclude_dirs=None):
    if os.path.isfile(arg) and os.path.exists(arg):
        outf = tempfile.NamedTemporaryFile(prefix="lexer_parser_output_", delete=False)
        outfile = outf.name
        process = None
        try:
            parsing_start = time.time()
            if log_std:
                process = Popen(["python", LEXER_PARSER_PATH, arg, rootdir, str(mode), outfile, str(flags), tag],
                                stdout=PIPE, stderr=PIPE)
            else:
                process = Popen(["python", LEXER_PARSER_PATH, arg, rootdir, str(mode), outfile, str(flags), tag],
                                stdout=DEVNULL, stderr=DEVNULL)
            output, error = process.communicate(timeout=timeout) if (timeout and timeout > 0) else process.communicate()
            ret = process.returncode
            logger.info("Parsing %s (status %d) under %s took %s seconds", arg, ret, rootdir,
                        time.time() - parsing_start)
        except TimeoutExpired as te:
            if process:
                process.terminate()
            output = error = None
            ret = 1
            logger.error("Error %s while parsing %s in mode %d", str(te), arg, mode)

        arg_features = None
        if ret == 0:
            # fix non-utf8, non-ascii code
            file2features = {}
            loaded_file2features = json.loads(open(outfile, 'r').read().decode('utf8', 'ignore'))
            for filepath, features in loaded_file2features.items():
                if features:
                    for feat_type in features:
                        # depending on flags, the value is different
                        if features[feat_type]:
                            if flags != FeatureFlags.NONE:
                                # location and group information are available
                                encoded_features = []
                                for value in features[feat_type]:
                                    # value is of type list
                                    if value is not None:
                                        value[0] = value[0].encode('utf8')
                                        encoded_features.append(value)
                                features[feat_type] = encoded_features
                            else:
                                # only feature is available
                                features[feat_type] = [value.encode('utf8') for value in features[feat_type] if
                                                       value is not None]
                        else:
                            features[feat_type] = []
                file2features[filepath] = features

            # only one file is parsed!
            arg_features = file2features[arg]

            # TODO: based on the flags, the output will be different!
        else:
            logger.error("Processing %s under root %s in mode %s failed!", arg, rootdir, mode)
            logger.error("STDOUT: %s\nSTDERR: %s", output, error)

        # clean up and return
        os.remove(outfile)
        yield arg, arg_features

    elif os.path.isdir(arg) and os.path.exists(arg):
        for dir_path, file_path in get_src_files(repo_path=arg, exclude_3rdparty=exclude_3rdparty,
                                                 exclude_dirs=exclude_dirs):
            # NOTE: For files, the parameter exclude_dirs doesn't have impact!
            yield list(
                callLexerParserSubprocess(arg=file_path, rootdir=rootdir, mode=mode, flags=flags, timeout=timeout,
                                          log_std=log_std, tag=tag, exclude_3rdparty=exclude_3rdparty,
                                          exclude_dirs=exclude_dirs))[0]


###########################################################
# Regular Expression-based String/Exported Function/System Calls Extractor
###########################################################
def extract_strings_regex(file_path):
    """
    Function to extract strings from a C source file.
    """
    # get all strings in this repo
    p = re.compile(
        r'(?P<prefix>(?:\bu8|\b[LuU])?)(?:"(?P<dbl>[^"\\]*(?:\\.[^"\\]*)*)"|\'(?P<sngl>[^\'\\]*(?:\\.[^\'\\]*)*)\')|R"([^"(]*)\((?P<raw>.*?)\)\4"')

    with open(file_path) as ins:
        for line in ins:
            line = line.rstrip('\n')

            # filter out "include *.c|cpp|cc|h"
            if re.search(r'\s*#\s*include\s*(?:<([^>]*)>|"([^"]*)")', line):
                continue

            # filter comments
            if re.search('//.*?\n|/\*.*?\*/|^\s*\*\s.*$', line):
                continue

            # iterate over them
            for x in p.finditer(line):
                if x.group("dbl"):
                    line = x.group("dbl")
                elif x.group("sngl"):
                    continue
                else:
                    line = x.group("raw")
                yield line


def loadtxt(file_path):
    f = open(file_path)
    txt = ''.join(f.readlines())
    f.close()
    return txt


def extract_functionnames_regex(file_path, exported_only=False):
    rproc = "(^|;|};?|public:|private:)"  # group 1: begining of source line
    rproc += "\s*"  # optional whitespace(s)
    rproc += "([\w_][\w\s\d_,<>\[\].&:\*]*)"  # group 2: return type (includes associated class)
    rproc += "\s+"  # mandatory whitespace(s)
    rproc += "(\*|[\*|\w_][\w\d_<>\*\[\]&]*::)?"  # group 3: # group 3: optional class/pointer type
    rproc += "([\w_][\w\d_]*)"  # group 4: function name
    rproc += "\s*"  # optional whitespace(s)
    rproc += "\("  # '(' start of parameters
    rproc += "([\w\s,<>\[\].=&':/*]*)"  # group 4: parameters
    rproc += "\)"  # ')' end of parameters
    rproc += "\s*"  # optional whitespace(s)
    rproc += "([\w\s\d_]*)"  # group 5: optional attribute
    rproc += "\s*"  # optional whitespace(s)
    rproc += "{"  # '{' function start

    p = re.compile(rproc)
    exclude = ['if', 'while', 'do', 'for', 'switch']
    for x in p.finditer(loadtxt(file_path)):
        if x.group(4) in exclude or (exported_only and 'static' in x.group(2)):
            continue
        yield x.group(4)


def extract_syscalls_regex(file_path):
    return []


def get_regex_syscalls(file_path):
    return [syscall for syscall in extract_syscalls_regex(file_path)]


###########################################################
# Prepare repo
###########################################################
def prepare_auto_configure(main, config_file, repo_path):
    """
    Instructions for auto configurations.
    http://www.sax.de/unix-stammtisch/docs/autotools/autotools.html
    http://www.aireadfun.com/blog/2012/12/03/study-automake/
    libtoolize && aclocal && autoheader && automake --add-missing && autoconf

    :param main: the detector object
    :param repo_path: path to the cloned repo
    """
    logger.info("executing %s", config_file)

    exec_command('libtoolize', ["libtoolize"], cwd=repo_path, timeout=main.CONFIGURE_TIMEOUT)
    exec_command('aclocal', ["aclocal"], cwd=repo_path, timeout=main.CONFIGURE_TIMEOUT)
    exec_command('autoheader', ["autoheader"], cwd=repo_path, timeout=main.CONFIGURE_TIMEOUT)
    exec_command('automake', ["automake", "--add-missing"], cwd=repo_path, timeout=main.CONFIGURE_TIMEOUT)
    exec_command('autoconf', ["autoconf"], cwd=repo_path, timeout=main.CONFIGURE_TIMEOUT)

    generated_configure = join(repo_path, 'configure')
    if exists(generated_configure):
        prepare_configure(main=main, config_file=generated_configure, repo_path=repo_path)
    else:
        logger.error("autoconf for %s failed!", config_file)


def prepare_configure(main, config_file, repo_path):
    logger.debug("%s exists. making it executable", config_file)

    # make sure "configure" is executable
    st = os.stat(os.path.join(repo_path, config_file))
    os.chmod(os.path.join(repo_path, config_file), st.st_mode | stat.S_IEXEC)

    logger.info("executing %s", config_file)

    # get ndk toolchain path
    ndk_toolchain = os.environ["NDK_TOOLCHAIN"]
    if not ndk_toolchain:
        raise Exception("$NDK_TOOLCHAIN environ variable not defined!")

    # configure exists, good to go
    args = ["sh", config_file, "--host=arm-linux-androideabi", "--with-sysroot=" + ndk_toolchain + "/sysroot"]
    retcode = exec_command(config_file, args, cwd=repo_path, timeout=main.CONFIGURE_TIMEOUT)
    if retcode:
        logger.error("configure %s failed", config_file)

        # failed with args, try with no args
        args = ["sh", config_file]
        retcode = exec_command(config_file, args, cwd=repo_path, timeout=main.CONFIGURE_TIMEOUT)

        # check if the makefile was generated
        if retcode or not os.path.isfile(os.path.join(repo_path, "Makefile")):
            logger.error("configure %s failed", config_file)
        else:
            # makefile successfully generated
            logger.info("%s finished! executing generated makefile", config_file)

            # execute make to generate any build dependent headers
            args = ["make"]
            retcode = exec_command("makefile", args, cwd=repo_path, timeout=5)
            if retcode:
                logger.error("make failed")
            else:
                logger.info("make done or timed out")


def prepare_repo(main, repo_id, branch, repo_path):
    """
    Prepares repo for lexer/parser
    returns nothing
    """
    # timed operation
    prepare_start = time.time()
    try:
        # check if "autogen" exists
        make_based_build_files = [filename for filename in os.listdir(repo_path)
                                  if make_based_build_files_pattern.search(filename)]

        if len(make_based_build_files) > 0:
            logger.debug("make-based build system detected")

            autogen_pattern = re.compile(r"""^autogen""", re.IGNORECASE)
            makefile_pattern = re.compile(r"""^makefile$""", re.IGNORECASE)

            # check if makefile exists
            makefiles = filter(makefile_pattern.match, make_based_build_files)
            if len(makefiles):
                logger.error("%s exists already. but trying to rebuild", makefiles)

            # iterate over all autogen files
            autogen_files = filter(autogen_pattern.match, make_based_build_files)
            for autogen_file in autogen_files:
                logger.debug("generating configure using %s", autogen_file)

                # make sure "autogen" is executable
                st = os.stat(os.path.join(repo_path, autogen_file))
                os.chmod(os.path.join(repo_path, autogen_file), st.st_mode | stat.S_IEXEC)

                # generate configure file
                args = ["sh", autogen_file]
                retcode = exec_command(autogen_file, args, cwd=repo_path, timeout=main.CONFIGURE_TIMEOUT)
                if retcode:
                    logger.error("%s failed", autogen_file)

            # detect configure files
            configure_pattern = re.compile(r"""^config""", re.IGNORECASE)
            configure_files = filter(configure_pattern.match, make_based_build_files)
            auto_configure_pattern = re.compile(r"""^configure\.(ac|in)$""", re.IGNORECASE)
            if not len(configure_files):
                raise Exception("no configure file detected")

            # iterate over all configure files
            for config_file in configure_files:
                if auto_configure_pattern.match(config_file):
                    prepare_auto_configure(main=main, config_file=config_file, repo_path=repo_path)
                else:
                    prepare_configure(main=main, config_file=config_file, repo_path=repo_path)

        else:

            # check if this repo uses a cmake-based build system
            cmake_based_build_files = [filename for filename in os.listdir(repo_path)
                                       if cmake_based_build_files_pattern.search(filename)]

            if len(cmake_based_build_files) > 0:

                # create build dir
                if not os.path.isdir(os.path.join(repo_path, "build")):
                    os.makedirs(os.path.join(repo_path, "build"))

                args = ["cmake", ".."]
                retcode = exec_command("cmake", args, cwd=os.path.join(repo_path, "build"),
                                       timeout=main.CONFIGURE_TIMEOUT)

                if retcode or not os.path.isfile(os.path.join(os.path.join(repo_path, "build"), "Makefile")):
                    raise Exception("cmake failed")

                # execute make to generate any build dependent headers
                args = ["make"]
                retcode = exec_command("makefile", args, cwd=os.path.join(repo_path, "build"), timeout=5)
                if retcode:
                    logger.error("make failed")

            # unknown build system
            else:
                raise Exception("unknown build system")

    except Exception as e:
        logger.error("Error configuring repo repo %s branch %s: %s", repo_id, branch, str(e))

    logger.info("preparing repo %s, branch %s, repo path %s, took time %s",
                repo_id, branch, repo_path, time.time() - prepare_start)


def get_regex_functionnames(file_path):
    return [func for func in extract_functionnames_regex(file_path, True)]


def get_regex_strings(file_path, string_list=None):
    if string_list is None:
        return [string for string in extract_strings_regex(file_path)]
    else:
        return string_list


def from_filter_list(repo_name, filter_list=('kernel', 'qemu', 'kvm', 'xen', 'u-boot', 'uboot')):
    return any(literal in repo_name for literal in filter_list)


# filter out unwanted tags
def skip_tag(main, tag):
    if main.INDEX_MAJOR_VERSIONS:
        tag = tag.lower()
        return any(term in tag for term in ['rc', 'alpha', 'beta', 'preview', 'unstable'])
    else:
        return True


def get_version_string(tag):
    # normal case: version.1.1
    # OpenSSL_1_0_1k, OpenSSL_0_9_7k
    # libpng-v1.0.5h
    all_numbers = re.findall('(\d+[a-zA-Z]*)', tag)
    return '.'.join(all_numbers)


def group_and_pick_tag(main, tags_commits):
    if main.INDEX_MAJOR_VERSIONS:
        version2tags_commits = {}
        for tag_commit in tags_commits:
            branch_tag, _ = tag_commit
            version_str = get_version_string(branch_tag)
            version2tags_commits.setdefault(version_str, [])
            version2tags_commits[version_str].append(tag_commit)

        # for every version, pick the latest/shortest?
        grouped_tags_commits = []
        for version in version2tags_commits:
            selected_tag_commit = sorted(version2tags_commits[version], key=lambda k: len(k[0]))[0]
            grouped_tags_commits.append(selected_tag_commit)
        return grouped_tags_commits
    else:
        return tags_commits


# filter out unwanted repos
def skip_repo(main, repo_id, repo_path, repo_name=None, repo_size=None):
    # must have a valid repo id
    if not repo_id.lstrip('-').isdigit():
        logger.info("skipping invalid repo id %s: %s", repo_id, repo_name)
        return True

    # filter by name
    if repo_name:
        repo_name = os.path.basename(repo_name)
        if from_filter_list(repo_name.lower()):
            logger.info("skipping filtered repo %s: %s", repo_id, repo_name)
            return True

    # filter by size
    if (repo_size and ((main.MIN_SIZE_C_CPP_FILES and int(repo_size) < main.MIN_SIZE_C_CPP_FILES)
                       or (main.MAX_SIZE_C_CPP_FILES and int(repo_size) > main.MAX_SIZE_C_CPP_FILES))):
        logger.info("skipping filtered repo %s size: %s: %s", repo_id, repo_size, repo_name)
        return True

    # if not yet clonned
    elif not repo_path:
        logger.info("skipping uncloned repo %s: %s", repo_id, repo_name)
        return False

    # check if repo exists
    elif not os.path.exists(repo_path):
        logger.info("skipping repo %s (%s) does not exist ", repo_path, repo_id)
        return True

    # check if repo is a dir
    elif not os.path.isdir(repo_path):
        logger.info("skipping repo %s is not a dir", repo_path)
        return True

    # check if repo is a git repo
    elif not os.path.exists(repo_path + "/.git"):
        logger.info("skipping repo %s is not a git repo", repo_path)
        return True

    # check if repo is Linux kernel
    elif os.path.exists(repo_path + "/Documentation") and \
            os.path.exists(repo_path + "/arch") and \
            os.path.exists(repo_path + "/mm") and \
            os.path.exists(repo_path + "/kernel") and \
            os.path.exists(repo_path + "/drivers"):
        return True

    # check if repo is uboot
    elif os.path.exists(repo_path + "/api") and \
            os.path.exists(repo_path + "/arch") and \
            os.path.exists(repo_path + "/board") and \
            os.path.exists(repo_path + "/common") and \
            os.path.exists(repo_path + "/nand_spl") and \
            os.path.exists(repo_path + "/drivers"):
        return True

    # all checks passed, do not skip this repo
    else:
        return False


###########################################################
# Repo clonner
###########################################################
def init_submodules(main, repo_path):
    try:
        import git
        repo = git.Repo(repo_path)

        logger.info("tags: %s", repo.tags)
        logger.info("tags: %s", sorted(repo.tags, key=lambda t: t.commit.committed_date))

        logger.info("initializing submodules for repo %s", repo_path)

        # register timeout handler
        with utils.time_limit(main.REPO_SUBMODULE_TIMEOUT):
            for submodule in repo.submodules:
                submodule.update(init=True, recursive=True)
            return True

    # timed out
    except utils.TimeoutException as te:
        logger.error("submodules %s", str(te))
        return True  # skip submodules

    except Exception as e:
        logger.error("failed to initialize submodules for repo %s: %s. ignoring!", repo_path, str(e))
        return True


def should_clone_tags(main, repo_name, filter_list=['stagefright', 'openssl']):
    # TODO: currently, we can use the filter_list to specify which library to clone versions. We need to be able to
    # choose among ('non tags', 'tags with maximum count', 'all tags')
    # return main.INDEX_REPO_VERSIONS and any(literal in repo_name.split('/', 1)[1] for literal in filter_list)
    return main.INDEX_REPO_VERSIONS


def clone_repo(main, repo_id, repo_name, repo_path, clone_tag=None, clone_latest_version=False):
    repo_url = main.REPO_URL_PROTOCOL + "://" + main.REPO_URL_HOSTNAME + "/" + repo_name

    if not should_clone_tags(main, repo_name) or clone_tag or clone_latest_version:

        # clone with depth = 1
        # first embed user account credentials in repo url
        repo_name, repo_url = main.Github.create_authenticated_repo_url(repo_url)
        if not repo_name or not repo_url:
            logger.error("Failed to parse repo url %s", repo_url)
            return None

        logger.info("cloning repo %s (%s) into %s", repo_id, repo_url, repo_path)
        try:
            tmp_repo_name = main.Github.clone_repo(repo_name=repo_name, repo_url=repo_url, repo_path=repo_path,
                                                   branch=clone_tag)
            if not tmp_repo_name:
                return None
        except Exception as e:
            logger.error("Failed to clone branch %s repo %s (%s) into %s: %s",
                         clone_tag, repo_id, repo_url, repo_path, str(e))

        if clone_tag:
            return [(clone_tag, repo_path)]
        else:
            try:
                commit_id = utils.get_git_log(repo_path, fmt='--pretty=%H', count=1)
            except Exception as e:
                raise Exception("failed to get commit id: " + str(e))
            return [(commit_id, repo_path)]

    else:

        # clone with all branches
        # clone branches now
        logger.info("cloning repo %s tags in %s", repo_name, repo_path)
        tags = None
        try:
            tags = main.Github.clone_tags(repo_url, repo_path)
        except:
            logger.error("Failed to clone tags for url %s", repo_url)
        # if there is branches/tags, then return them, o.w. clone the latest version!
        return tags if tags else clone_repo(main, repo_id, repo_name, repo_path, clone_latest_version=True)


def delete_repo(repo_path):
    if os.path.isdir(repo_path):
        shutil.rmtree(repo_path)


def build_features_pb(repo_path, dir2license, file2features, branch_details, flags):
    # fix encoding in protobuf (http://www.cnblogs.com/tangkaixin/p/4846962.html)
    def _clean_assign(proto, field, value):
        try:
            setattr(proto, field, value)
        except ValueError as ve:
            setattr(proto, field, value.decode('utf8'))

    # fill into root proto
    features_pb = files_pb.AllFilesSummary()
    features_pb.root_path = repo_path
    features_pb.timestamp = str(time.time())
    features_pb.info.id = branch_details['repo_id']
    features_pb.info.name = branch_details['repo_name']
    features_pb.info.tag = branch_details['branch']
    if repo_path in dir2license:
        features_pb.info.licenses.extend(set(dir2license[repo_path]['license']))

    path2pb = {}
    for node, licenses in dir2license.items():
        if node not in path2pb:
            node_proto = features_pb.dirs.add()
            path2pb[node] = node_proto
        else:
            node_proto = path2pb[node]
        _clean_assign(node_proto, 'name', basename(node))
        _clean_assign(node_proto, 'path', node)
        node_proto.licenses.extend(set(licenses['license']))
        node_proto.license_filenames.extend(licenses['license_filename'])

    # private function used to build feat proto
    def _build_per_feature_pb(typ, feat, flags, func_name=None):
        feat_pb = None
        try:
            # create pb object
            if typ in ('string_literal', 'variable'):
                feat_pb = files_pb.DataProto()
            elif typ in ('exported_function',):
                feat_pb = files_pb.MethodAttributeProto()
            else:
                raise Exception("Unexpected feature type: " + typ)

            # set values
            if flags == FeatureFlags.NONE:
                if typ == 'exported_function':
                    # MethodAttributeProto
                    feat_pb.method_name = func_name
                    feat_pb.method_signature = feat
                elif typ == 'string_literal':
                    # DataProto
                    feat_pb.type = files_pb.DataProto.STRING_CONSTANT
                    _clean_assign(feat_pb, 'value', feat)
                elif typ == 'variable':
                    # DataProto
                    feat_pb.type = files_pb.DataProto.GLOBAL_VARIABLE
                    feat_pb.value = feat
            else:
                index = 0
                if typ == 'exported_function':
                    # MethodAttributeProto
                    feat_pb.method_name = func_name[index]
                    feat_pb.method_signature = feat[index]
                elif typ == 'string_literal':
                    # DataProto
                    feat_pb.type = files_pb.DataProto.STRING_CONSTANT
                    # TODO: fix bug here 'fd\xc3\xa7\xc3\xa7\xc3\xa7\xc3\xa7\xc3\xa7\xc3\xa7\xc3\xa7\xc3\xa7\xc3'
                    _clean_assign(feat_pb, 'value', feat[index])
                elif typ == 'variable':
                    feat_pb.type = files_pb.DataProto.GLOBAL_VARIABLE
                    feat_pb.value = feat[index]
                # include group information
                if flags & FeatureFlags.GROUP:
                    index += 1
                    feat_pb.location_info.group = feat[index]
                # ignore non-exported functions
                if flags & FeatureFlags.EXPORT_TYPE:
                    index += 1
                    if feat[index] & FunctionType.EXPORT_FUNCTION:
                        feat_pb.export_type = feat[index]
                    else:
                        return None
                # include location information
                if flags & FeatureFlags.LOCATION:
                    index += 1
                    (feat_pb.location_info.start.row, feat_pb.location_info.start.column,
                     feat_pb.location_info.end.row, feat_pb.location_info.end.column) = feat[index:index + 4]
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logger.error("[%s, %s, %s] Error when building feature pb for %s, %s, %s: %s",
                         exc_type, fname, exc_tb.tb_lineno, typ, feat, flags, str(e))

        return feat_pb

    for leaf, features in file2features.items():
        # features can map feat_type to list of features or list of feature lists (with location and group information)
        if leaf not in path2pb:
            leaf_proto = features_pb.files.add()
            path2pb[leaf] = leaf_proto
        else:
            leaf_proto = path2pb[leaf]
        _clean_assign(leaf_proto, 'name', basename(leaf))
        _clean_assign(leaf_proto, 'path', leaf)
        leaf_proto.mode = features['mode']

        # Set syscalls and licenses!
        if 'system_call' in features and len(features['system_call']) > 0:
            leaf_proto.syscalls.extend(features['system_call'])
        if 'license' in features and len(features['license']) > 0:
            leaf_proto.licenses.extend(set(features['license']))

        # Set methods/strings! classes/globals are not available yet!
        # Mode LEXER -> only string have location info, mode PARSER -> all features have location info
        for s in features['string_literal']:
            s_pb = _build_per_feature_pb(typ='string_literal', feat=s, flags=flags)
            if s_pb:
                n_pb = leaf_proto.strings.add()
                n_pb.CopyFrom(s_pb)
        if features['mode'] == files_pb.LEXER:
            tmp_flags = FeatureFlags.NONE
        else:
            tmp_flags = flags
        for v in features['variable']:
            v_pb = _build_per_feature_pb(typ='variable', feat=v, flags=flags)
            if v_pb:
                n_pb = leaf_proto.globals.add()
                n_pb.CopyFrom(v_pb)
        for fn, f in zip(features['exported_function_name'], features['exported_function']):
            # the function name and function are dumped in the same order in LexerParser.cpp
            f_pb = _build_per_feature_pb(typ='exported_function', feat=f, flags=tmp_flags, func_name=fn)
            if f_pb:
                n_pb = leaf_proto.methods.add()
                n_pb.CopyFrom(f_pb)

    return features_pb


def get_outname(repo_id, branch, suffix):
    if branch:
        return repo_id + '-' + branch + suffix
    else:
        return repo_id + suffix


def signature(main, branch_details, branch_path, item, cloned=False):
    features_pb = None
    repo_id = branch_details['repo_id']
    repo_name = branch_details['repo_name']
    branch = branch_details['branch']

    # make sure everything is cloned
    if not cloned:
        # start shallow cloning requested repo
        shallow_clone_start = time.time()
        res = None
        try:
            res = clone_repo(main=main, repo_id=repo_id, repo_name=repo_name, repo_path=branch_path, clone_tag=branch)
        except Exception as be:
            logger.error("clone repo %s, name %s failed! Error: %s!", repo_id, repo_name, str(be))
        logger.info("clone repo %s, name %s, path %s took %s", repo_id, repo_name, branch_path,
                    time.time() - shallow_clone_start)
        if not res:
            delete_repo(branch_path)
            return 0

        # in case of versions, new_repo_path points to the top repo dir containing all
        # version dirs, so defer skip_repo() until later when we iterate over each version
        if not should_clone_tags(main, repo_name) and skip_repo(main, repo_id, branch_path):
            delete_repo(branch_path)
            return 0

    # check if we need to skip
    if should_clone_tags(main, repo_name) and skip_repo(main, repo_id, branch_path):
        if not item.isdigit() or int(item) < 0:
            delete_repo(branch_path)
        return 0

    # if index submodules, make sure they are available
    if main.INDEX_SUBMODULES and not init_submodules(main, branch_path):
        if not item.isdigit() or int(item) < 0:
            delete_repo(branch_path)
        return 0

    # make sure repo path exists
    if not os.path.isdir(branch_path):
        logger.error("repo %s branch %s path %s does not exist!", repo_name, branch, branch_path)
        return 0

    # try to do prep repo (autogen && configure)
    prepare_repo(main=main, repo_id=repo_id, branch=branch, repo_path=branch_path)

    # extract features from repo and store into features_pb
    # TODO: merge license and feature parsing!
    # TODO: add feature location information!
    try:
        # find all license-like files and map the directory to the license (one dir may contain multiple licenses)
        dir2license = {}
        # for dir_path, license_path in get_license_files(repo_path):
        for dir_path, license_path in get_license_files(branch_path, get_thirdparty_file=True):
            licenses = None
            if is_independent_file(license_path):
                # use this word as placeholder for non-license third-party files (ps. branch_path cannot be third-party)
                if branch_path != dir_path:
                    licenses = ['THIRD-PARTY']
            else:
                try:
                    licenses = get_license_info_wrapper(filename=license_path)
                except Exception as e:
                    logger.error("Error detecting license for %s: %s, Ignoring!", license_path, str(e))
            if licenses and not (len(licenses) == 1 and licenses[0] in ('', 'See-file', 'See-doc(OTHER)', 'See-doc')):
                dir2license.setdefault(dir_path, {'license_filename': [], 'license': []})
                dir2license[dir_path]['license_filename'].append(basename(license_path))
                dir2license[dir_path]['license'].extend(licenses)

        # NOTE: exclude_dirs is only used to optimize indexing performance!
        # exclude_dirs are dirs (excluding root) with license or independent files, but is not similar to repo_artifact and source
        repo_group, repo_artifact = repo_name.split('/', 1)
        exclude_dirs = {dir_path for dir_path in dir2license if
                        dir_path != branch_path and not re.search(source_pattern, dir_path) and
                        levenshtein(basename(dir_path), repo_artifact, True) > main.MAX_NAME_DISTANCE}

        # find all 'c,c++' source files
        file2features = {}
        # output location and group information
        lexer_parser_flags = FeatureFlags.EXPORT_TYPE | FeatureFlags.LOCATION
        if main.USE_IFDEF_GROUP:
            lexer_parser_flags |= FeatureFlags.GROUP
        for file_path, features in callLexerParserSubprocess(arg=branch_path, rootdir=branch_path,
                                                             flags=lexer_parser_flags,
                                                             timeout=main.LEXER_TIMEOUT, log_std=True, tag=branch,
                                                             exclude_3rdparty=True, exclude_dirs=exclude_dirs):

            # node path
            if not main.TEST_REPO:
                logger.debug("Working with leaf node %s ", file_path)

            if features is None:
                # If the Parsing fails, try the regex based approach!
                # Possibly failed to process the file! fallback to regex based approach.
                logger.info(
                    "Building feat database for repo %s, branch %s, file path %s, using parser failed! try lexer!",
                    repo_id, branch, file_path)
                # there is only one file being processed
                arg_file_path, features = list(
                    callLexerParserSubprocess(arg=file_path, rootdir=branch_path, mode=0, flags=lexer_parser_flags,
                                              timeout=main.LEXER_TIMEOUT, tag=branch, exclude_3rdparty=True,
                                              exclude_dirs=exclude_dirs))[0]
                if features is None:
                    logger.info(
                        "Building feat database for repo %s, branch %s, file path %s, using lexer failed! try regex!",
                        repo_id, branch, file_path)
                    strings = get_regex_strings(file_path=file_path)
                else:
                    strings = features['string_literal'] if 'string_literal' in features else []
                    if main.USE_IFDEF_GROUP:
                        strings = [feat[0] for feat in strings]
                functionnames = get_regex_functionnames(file_path=file_path)
                functions = []
                variables = []
                syscalls = get_regex_syscalls(file_path=file_path)
                mode = files_pb.LEXER

            else:
                # get all features in this file
                strings = features['string_literal']
                functionnames = features['exported_function_name']
                functions = features['exported_function']
                variables = features['variable']
                syscalls = features['system_call']
                mode = files_pb.PARSER
                if main.USE_IFDEF_GROUP:
                    strings = [feat[0] for feat in strings]
                    functionnames = [feat[0] for feat in functionnames]
                    functions = [feat[0] for feat in functions]
                    variables = [feat[0] for feat in variables]
                    syscalls = [feat[0] for feat in syscalls]

            file2features[file_path] = {'string_literal': strings, 'exported_function_name': functionnames,
                                        'exported_function': functions, 'variable': variables, 'system_call': syscalls,
                                        'mode': mode}
            if main.SCAN_FILES_FOR_LICENSE:
                licenses = None
                try:
                    licenses = get_license_info_wrapper(filename=file_path)
                except Exception as e:
                    logger.error("Error detecting license for %s: %s, Ignoring!", file_path, str(e))
                if licenses and not (
                        len(licenses) == 1 and licenses[0] in ('', 'See-file', 'See-doc(OTHER)', 'See-doc')):
                    logger.info("detected license %s in file %s", licenses, file_path)
                    file2features[file_path]['license'] = licenses

        features_pb = build_features_pb(repo_path=branch_path, dir2license=dir2license,
                                        file2features=file2features, branch_details=branch_details,
                                        flags=lexer_parser_flags)

        # output signature file to tmp folder, to speed up program
        tmp_outfile = join('/tmp/', get_outname(repo_id=repo_id, branch=branch, suffix=SIG_SUFFIX))
        write_proto_to_file(proto=features_pb, filename=tmp_outfile, binary=main.binary_sig)
        if main.compress_sig:
            outfile = join(main.repo_sig_dir, get_outname(repo_id=repo_id, branch=branch, suffix=SIG_ZIP_SUFFIX))
        else:
            outfile = join(main.repo_sig_dir, get_outname(repo_id=repo_id, branch=branch, suffix=SIG_SUFFIX))

        # if compress signature, then zip it and remove the resulting signature file
        if main.compress_sig:
            tmp_outfile = zip_and_remove(tmp_outfile)
        shutil.move(tmp_outfile, outfile)

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error("[%s, %s, %s] Error when extracting signature for %s, branch %s: %s",
                     exc_type, fname, exc_tb.tb_lineno, repo_id, branch, str(e))

    return features_pb


def get_all_files_summary(main, root_repo_path, item, branch=None):
    """
    Get the summary of all files in the branch of repo.

    :param main: main object
    :param root_repo_path: root for cloning
    :param item: repo name
    :param branch: repo tag/branch
    :return: dir2license, file2features
    """
    stats_summary_time = time.time()

    is_cloned = False
    # make directory if it doesn't exist
    if not os.path.exists(main.repo_sig_dir):
        os.makedirs(main.repo_sig_dir)
    # build repo path
    if not item.isdigit() or int(item) < 0:

        # item is repo url
        repo_id, repo_name = item.split(",", 1)
        if branch:
            repo_path = os.path.join(root_repo_path, repo_id, branch.replace('/', '_'))
            # postpone the clone operation, since the signature might have been cached!
            branches = [(branch, repo_path)]

        else:
            # TODO: clone branches, but is this actually needed?
            repo_path = os.path.join(root_repo_path, repo_id)
            is_cloned = True
            branches = None
            deep_clone_start = time.time()
            try:
                branches = clone_repo(main=main, repo_id=repo_id, repo_name=repo_name, repo_path=repo_path)
            except Exception as be:
                logger.error("clone repo %s, name %s failed! Error: %s!", repo_id, repo_name, str(be))
            logger.info("clone repo %s, name %s, path %s took %s", repo_id, repo_name, repo_path,
                        time.time() - deep_clone_start)
            if not branches:
                delete_repo(repo_path)
                return 0

            # in case of versions, new_repo_path points to the top repo dir containing all
            # version dirs, so defer skip_repo() until later when we iterate over each version
            if not should_clone_tags(main, repo_name) and skip_repo(main, repo_id, repo_path):
                delete_repo(repo_path)
                return 0

    else:
        # Pointing to a folder that has been locally cloned! Not cached!
        repo_id = repo_name = item
        repo_path = os.path.join(root_repo_path, repo_id)
        is_cloned = True
        if branch:
            # TODO: this code seems outdated! I guess only tag is available now!
            tag, commit = branch
            if not utils.checkout_git_tag(repo_path, tag):
                logger.error("failed to checkout tag %s of repo %s at repo_path %s", tag, repo_id, repo_path)
                return
            branches = [(tag, repo_path)]
        else:
            commit_id = utils.get_git_log(repo_path, fmt='--pretty=%H', count=1)
            branches = [(commit_id, repo_path)]

    # signature branches if requested
    signature_results = []
    for branch, branch_path in branches:
        # main.keep_sig must be true, otherwise this is meaningless
        # assert main.keep_sig and main.repo_sig_dir
        #
        # compute the expected output filename
        branch_details = {'branch': branch, 'repo_id': repo_id, 'repo_name': repo_name}
        expected_outname = None
        expected_outname_exists = False
        if main.reuse_sig:
            if main.compress_sig:
                expected_outname = join(main.repo_sig_dir,
                                        get_outname(repo_id=repo_id, branch=branch, suffix=SIG_ZIP_SUFFIX))
            if os.path.exists(expected_outname):
                expected_outname_exists = True

        if main.reuse_sig and expected_outname_exists:
            # Reusing previously generated signature results
            logger.info("reusing previous generated signature file %s for %s, branch %s",
                        expected_outname, item, branch)
            afs = files_pb.AllFilesSummary()
            if main.compress_sig:
                content_string = read_from_zipfile(expected_outname, splitext(basename(expected_outname))[0])
                read_proto_from_string(proto=afs, content_string=content_string, binary=main.binary_sig)
            else:
                read_proto_from_file(proto=afs, filename=expected_outname, binary=main.binary_sig)
            branch_details['branch_path'] = afs.root_path
        elif main.skip_no_sig:
            logger.info("skipping %s, branch %s, because it doesn't have the previous generated signature file %s!",
                        item, branch, expected_outname)
            afs = files_pb.AllFilesSummary()
            branch_details['branch_path'] = branch_path
        else:
            branch_details['branch_path'] = branch_path
            # Generate signature for the current repo and branch
            afs = signature(main=main, branch_details=branch_details, branch_path=branch_path, item=item,
                            cloned=is_cloned)
            is_cloned = True

        # convert afs to dir2license and file2features
        dir2license = {}  # dir path -> license
        file2features = {}  # file path -> {'exported_function': XX, '': YY, ..}
        for dir_proto in afs.dirs:
            # update dir2license
            if len(dir_proto.licenses) > 0:
                # third party is marked license THIRD-PARTY
                dir2license.setdefault(dir_proto.path, list(dir_proto.licenses))
        for file_proto in afs.files:
            # get the string_literal, string_literal may be unicode, encode it in utf8
            file2features.setdefault(file_proto.path, {
                'string_literal': [s.value.encode('utf8') for s in file_proto.strings],
                'system_call': list(file_proto.syscalls),
                'variable': [v.value for v in file_proto.globals], 'license': list(file_proto.licenses),
                'exported_function': [], 'exported_function_name': []})
            # get functions
            for method in file_proto.methods:
                file2features[file_proto.path]['exported_function'].append(method.method_signature)
                file2features[file_proto.path]['exported_function_name'].append(method.method_name)
            # get classes
            for class_proto in file_proto.classes:
                for method in class_proto.methods:
                    file2features[file_proto.path]['exported_function'].append(method.method_signature)
                    file2features[file_proto.path]['exported_function_name'].append(method.method_name)

        # Log time if requested
        if stats_logger:
            stats_logger.info("time elapsed for getting summary for %s, branch %s is %0.2f seconds",
                              item, branch, time.time() - stats_summary_time)

        signature_results.append([branch_details, dir2license, file2features])

    # done; delete git repo
    if is_cloned and (not item.isdigit() or int(item) < 0):
        delete_repo(repo_path)

    return signature_results


def signature_repo(main, root_repo_path, item, branch=None):
    start = time.time()
    # global values
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger

    # get the features for repo
    _, summary_dict = get_all_files_summary(main, root_repo_path, item, branch)
    files_n = len(summary_dict)
    func_n = 0
    funcname_n = 0
    string_n = 0
    syscall_n = 0
    for filename, fileattr in summary_dict.items():
        if 'exported_function' in fileattr:
            func_n += len(fileattr['exported_function'])
        if 'exported_function_name' in fileattr:
            funcname_n += len(fileattr['exported_function_name'])
        if 'string_literal' in fileattr:
            string_n += len(fileattr['string_literal'])
        if 'system_call' in fileattr:
            syscall_n += len(fileattr['system_call'])
    # time logging
    end = time.time()
    if stats_logger:
        stats_logger.info("time elapsed for signaturing %s-%s: %0.2f seconds", item, branch, end - start)
        stats_logger.info("%s-%s, files %d, func %d, funcname %d, string %d, syscall %d",
                          item, files_n, func_n, funcname_n, string_n, syscall_n)


def get_repo_list(main, redis, arg):
    repo_list = []

    # single repo dir
    if os.path.isdir(arg) and os.path.exists(arg + "/.git"):
        repo_path = arg
        repo_id = os.path.basename(repo_path)
        if main.TEST_REPO and not skip_repo(main, repo_id, repo_path):
            repo_list.append(repo_id)
        elif not skip_repo(main, repo_id, repo_path) and (
            not repo_scanned(redis, repo_id) or (main.INDEX_REPO_VERSIONS and main.INDEX_MAJOR_VERSIONS)):
            repo_list.append(repo_id)

    # root repo dir
    elif os.path.isdir(arg):
        for repo_id in os.listdir(arg):
            repo_path = os.path.join(arg, repo_id)
            if not skip_repo(main, repo_id, repo_path) and (
                not repo_scanned(redis, repo_id) or (main.INDEX_REPO_VERSIONS and main.INDEX_MAJOR_VERSIONS)):
                repo_list.append(repo_id)

    # file containing list of repos
    elif os.path.isfile(arg):
        try:
            import csv, json
            csv_file = open(arg)
            reader = csv.DictReader(csv_file, delimiter=',')
            has_tag = 'tag' in reader.fieldnames
            logger.info("Building repo list")

            # register signal handler
            signal = utils.Signal()
            signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

            # parse file containing repo list
            count = 0
            for row in reader:
                # Get the parameters
                repo_id = row['gh_id']
                repo_name = row['full_name']
                repo_url = row['html_url']
                primary_language = row['primary_language']
                all_languages = json.loads(row['languages'])
                subscribers_count = row['subscribers_count']
                stargazers_count = row['stargazers_count']
                forks_count = row['forks_count']
                created_at = row['created_at']
                updated_at = row['updated_at']
                pushed_at = row['pushed_at']
                repo_size = row['size']
                if has_tag:
                    tag = row['tag']
                    sha = row['sha']
                    # row_date = row['date']

                # check for interruption
                if signal.caught():
                    logger.error("Interrupted")
                    return None

                # consider only c/c++ repos
                c_cpp_size = 0
                for lang, lang_size in all_languages.items():
                    if lang.lower() == 'c' or lang.lower() == 'c++':
                        c_cpp_size += lang_size

                if c_cpp_size == 0:
                    logger.info("skipping %s (primary_language: %s): %s",
                                repo_id, primary_language, all_languages)
                    continue

                # build list
                if not skip_repo(main, repo_id, None, repo_name, c_cpp_size):
                    if main.INDEX_REPO_VERSIONS and main.INDEX_MAJOR_VERSIONS:
                        if has_tag:
                            repo_list.append((repo_id + "," + repo_name, (tag, sha)))
                        else:
                            repo_list.append(repo_id + "," + repo_name)
                    else:
                        if not repo_scanned(redis, repo_id):
                            repo_list.append(repo_id + "," + repo_name)

            if has_tag:
                repo2tags = {}
                for repo, tag_commit in repo_list:
                    repo2tags.setdefault(repo, [])
                    tag, commit = tag_commit
                    if tag and commit:
                        repo2tags[repo].append(tag_commit)
                repo_list = repo2tags.items()

        except Exception as e:
            logger.error("Error parsing repo list file %s: %s", arg, str(e))

    if main.SHUFFLE_INPUT:
        random.shuffle(repo_list)

    return repo_list


###########################################################
# Repo filter
###########################################################
def repo_scanned(redis, repo_id, branch=None):
    try:
        if branch:
            branch_id = get_typed_key(typ=repo_id, key=branch)
            exists = redis.exists(get_typed_key('branch', branch_id))
        else:
            exists = redis.exists(get_typed_key('repo', repo_id))
        if exists:
            logger.debug("repo %s branch %s already indexed", repo_id, branch)
            return True
        return False

    except Exception as e:
        logger.error("repo_scanned: error %s", str(e))
        return False


def fetch_and_filter_repo_list(main, url_or_path):
    redis = main.nrc.handle()

    # check if url_or_path is a URL to a repo
    parsed_url = urlparse.urlparse(url_or_path)
    can_index_versions = False
    if parsed_url.scheme:

        # check if supported
        if (parsed_url.scheme != main.REPO_URL_PROTOCOL or parsed_url.netloc != main.REPO_URL_HOSTNAME):
            logger.error("%s://%s not supported", parsed_url.scheme, parsed_url.netloc)
            exit(1)

        # get repo_id and repo_name
        repo_id = random.randint(-9999, -1)
        repo_name = parsed_url.path.lstrip('/')
        root_repo_path = None
        repo_list = [str(repo_id) + "," + repo_name]

    else:

        # check if path exists
        if not os.path.exists(url_or_path):
            logger.error('%s does not exist', url_or_path)
            exit(1)

        if os.path.isdir(url_or_path) and os.path.exists(url_or_path + "/.git"):

            # scan single repo
            root_repo_path = os.path.dirname(url_or_path)
            repo_list = get_repo_list(main, redis, url_or_path)
            # count = 1

        elif os.path.isdir(url_or_path):

            # build repo list
            root_repo_path = url_or_path
            repo_list = get_repo_list(main, redis, url_or_path)

        elif os.path.isfile(url_or_path):

            # argv[1] is a list of repos
            if not main.REPO_SOURCE and not main.REPO_ROOT_URL:
                logger.error("REPO_SOURCE missing from config")
                exit(1)

            # build repo list
            root_repo_path = None
            repo_list = get_repo_list(main, redis, url_or_path)
            can_index_versions = True

        else:
            logger.error("invalid option")
            exit(1)

    if main.INDEX_REPO_VERSIONS and can_index_versions:
        # query the tags for all the repos to index, if the tags information is not available, insert them into
        # back into postgresql database! This needs to be done only once!
        new_repo_list = []
        for repo in repo_list:
            if isinstance(repo, tuple):
                # loaded repos and tags commits
                repo, tags_commits = repo
                gh_id, full_name = repo.split(',')
                tag_count = len(tags_commits)
                if tag_count == 0:
                    # no tags found
                    logger.info("no tags found for %s", repo)
                    if not repo_scanned(redis=redis, repo_id=gh_id, branch=None):
                        new_repo_list.append((repo, None))
                    continue

            else:
                # repo: gh_id,full_name
                logger.info("fetching tags for repo: %s", repo)
                gh_id, full_name = repo.split(',')

                # query tag count first
                tag_count = main.Github.get_tag_count_from_db(full_name)
                logger.info("repo has %d tags", tag_count)
                if tag_count == 0:
                    # no tags found
                    logger.info("no tags found for %s", repo)
                    if not repo_scanned(redis=redis, repo_id=gh_id, branch=None):
                        new_repo_list.append((repo, None))
                    continue

                # if tag count is not available, query github
                if tag_count is None or tag_count <= -1:
                    # query GitHub and fill in postgresql database
                    logger.info("haven't checked repo tags %s yet! directly query GitHub to get this information",
                                full_name)
                    repo_owner, repo_name = full_name.split('/')
                    main.Github.get_tags_commits(repo_owner=repo_owner, repo_name=repo_name, insertdb=True, gh_id=gh_id)

                # query tag count again, should be ready now!
                tag_count = main.Github.get_tag_count_from_db(full_name)
                if tag_count == 0:
                    # no tags found
                    logger.info("no tags found for %s", repo)
                    if not repo_scanned(redis=redis, repo_id=gh_id, branch=None):
                        new_repo_list.append((repo, None))
                    continue

                # select the tag commits from crawled tags
                _, sorted_tags_commits = main.Github.get_tags_from_db(full_name=full_name, return_obj=False)
                tags_commits = [tag_commit for _, tag_commit in sorted_tags_commits.items()]

            # filter the sorted_tags_commits
            logger.info("repo %s has %d tags", gh_id, len(tags_commits))
            new_tags_commits = []
            valid_tag_count = 0
            for tag_commit in tags_commits:
                branch_tag, _ = tag_commit
                if not skip_tag(main, branch_tag) and not repo_scanned(redis=redis, repo_id=gh_id, branch=branch_tag):
                    valid_tag_count += 1
                    new_tags_commits.append(tag_commit)
            logger.info("repo %s filtered %d tags into %d tags", full_name, tag_count, valid_tag_count)
            grouped_tags_commits = group_and_pick_tag(main, new_tags_commits)
            if grouped_tags_commits:
                logger.info("repo %s grouped %d tags into %d tags", full_name, valid_tag_count,
                            len(grouped_tags_commits))
            for branch_tag, _ in grouped_tags_commits:
                new_repo_list.append((repo, branch_tag))

        repo_list = new_repo_list

    else:
        repo_list = [(repo, None) for repo in repo_list]
    return root_repo_path, repo_list


###########################################################
# Signature
###########################################################
def run(main, argv):
    global logger, stats_logger
    logger = main.logger
    stats_logger = main.stats_logger

    # the outer args
    if len(argv) != 2:
        logger.error('expects two args')
        exit(1)
    if argv[0] == 'dump' or argv[0] == 'stats':
        main.TEST_REPO = True
    if argv[0] == 'stats':
        main.STATS = True

    # prepare repo list
    root_repo_path, repo_list = fetch_and_filter_repo_list(main=main, url_or_path=argv[1])
    if main.SHUFFLE_INPUT:
        random.shuffle(repo_list)

    # start scanning
    if repo_list:

        # how many repos
        count = len(repo_list)
        logger.info("Request to signature %s repos", count)

        # register signal handler
        signal = utils.Signal()
        signal.install([utils.Signal.SIGINT, utils.Signal.SIGTERM])

        # track progress
        if main.TEST_REPO:
            pb = utils.Progressbar('Testing repos: ', count)
        else:
            pb = utils.Progressbar('Indexing repos: ', count)
        pb.start()

        # create root repo dir if doesn't exist
        ts = None
        if not root_repo_path:
            try:
                ts = time.strftime('%Y_%m_%d_%H_%M_%S')
                root_repo_path = "/tmp/" + os.path.basename(argv[1]) + "_" + ts
                os.mkdir(root_repo_path)
            except Exception as e:
                logger.error("Error creating root_repo_path %s: %s", root_repo_path, str(e))
                return

        # if we are testing
        test = None
        if main.STATS:
            test = 'stats'
        elif main.TEST_LIB:
            test = 'dump'

        # if requested parallelism
        if main.QUEUING and main.QUEUING == "Celery":
            from celery import group
            from celery_tasks import native_signature_worker

            # group jobs
            job = group(native_signature_worker.s(repo_path=root_repo_path, repo_id=item, branch=branch, test=test)
                        for item, branch in repo_list)
            result = job.apply_async()

            # track worker progress
            completed = 0
            while (result.waiting()):
                completed += result.completed_count()
                if completed < count:
                    pb.update(completed)
                time.sleep(2)

            # all done
            pb.finish()
            count = completed

        else:  # non-parallel instance

            count = 0

            # scan loop
            for item, tag in repo_list:

                # check for interruption
                if signal.caught():
                    break

                # item is a tuple <repo id, repo url>
                if not item.isdigit() or int(item) < 0:
                    repo_id, repo_name = item.split(",")
                else:
                    repo_id = item

                if main.TEST_REPO:
                    pb.msg('Testing {0} '.format(repo_id))
                else:
                    pb.msg('Indexing {0} '.format(repo_id))

                # scan repo; already filtered
                if signature_repo(main, root_repo_path, item, branch=tag):
                    count += 1

                # update progressbar
                pb.update(count)

            if not signal.caught():
                pb.finish()

        # delete root_repo_path
        if ts:
            shutil.rmtree(root_repo_path)

        # log number of repos indexed (not relevant though)
        total = main.nrc.handle().get("repos")
        if total:
            if main.TEST_REPO:
                logger.critical("Indexed a total of %s repos (tested %d)", total, count)
            else:
                logger.critical("Indexed a total of %s repos (new: %d)", total, count)
