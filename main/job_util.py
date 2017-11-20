import glob, gflags
import json, logging
import os
import hashlib
import sys
import signal
import psutil

from protobuf_to_dict import protobuf_to_dict, dict_to_protobuf
from multiprocessing import Pool, Manager
from google.protobuf.text_format import MessageToString, Merge

FLAGS = gflags.FLAGS


###########################################################
# Utilities for file system
###########################################################
def list_recursive(indir, prefix=None, suffix=None, case_insensitive=False):
    files_to_aggregate = []  # used to record files with distinct URIs
    if case_insensitive:
        prefix = prefix.lower() if prefix else prefix
        suffix = suffix.lower() if suffix else suffix
    for dirName, subdirList, fileList in os.walk(indir):
        for fname in fileList:
            filepath = os.path.join(dirName, fname)
            check_fname = fname.lower() if case_insensitive else fname
            if prefix and check_fname.startswith(prefix):
                files_to_aggregate.append(filepath)
            if suffix and check_fname.endswith(suffix):
                files_to_aggregate.append(filepath)
    return files_to_aggregate


def list_recursive_unique_filename(indir, prefix=None, suffix=None, case_insensitive=False):
    fname2filepath = {}  # used to record files with distinct filenames
    if case_insensitive:
        prefix = prefix.lower() if prefix else prefix
        suffix = suffix.lower() if suffix else suffix
    for dirName, subdirList, fileList in os.walk(indir):
        for fname in fileList:
            filepath = os.path.join(dirName, fname)
            check_fname = fname.lower() if case_insensitive else fname
            if prefix and check_fname.startswith(prefix):
                fname2filepath[fname] = filepath
            if suffix and check_fname.endswith(suffix):
                fname2filepath[fname] = filepath
    return fname2filepath


def getExcludeFilename(prefix=None, infile=None, log_file=None, job=None):
    if not prefix:
        prefix = 'exclude'
    if not infile:
        infile = FLAGS.infile
    if not log_file:
        log_file = FLAGS.log_file
    if not job:
        job = FLAGS.job
    # the exclude file is stored as ./log/$prefix-$job_name-$in_filename
    inname = os.path.basename(infile)
    log_dir = os.path.dirname(log_file)
    exclude_filename = os.path.join(log_dir, '%s-%s-%s' % (prefix, job, inname))
    return exclude_filename


def getExcludeList(infile):
    # the exclude file is stored as ./log/exclude-$job_name-$infile_md5
    exclude_filename = getExcludeFilename(infile)
    if os.path.exists(exclude_filename):
        return filter(bool, open(exclude_filename, 'r').read().split('\n'))
    else:
        return []


###########################################################
# Utilities for protocol buffer IO
###########################################################
def write_proto_to_file(proto, filename, binary=True):
    if binary:
        f = open(filename, "wb")
        f.write(proto.SerializeToString())
        f.close()
    else:
        f = open(filename, "w")
        f.write(MessageToString(proto))
        f.close()


def read_proto_from_file(proto, filename, binary=True):
    if binary:
        f = open(filename, "rb")
        proto.ParseFromString(f.read())
        f.close()
    else:
        f = open(filename, "r")
        Merge(f.read(), proto)
        f.close()


def read_proto_from_string(proto, content_string, binary=True):
    if binary:
        proto.ParseFromString(content_string)
    else:
        Merge(content_string, proto)


###########################################################
# Utilities for multithreading
###########################################################
class Watcher:
    """this class solves two problems with multithreaded
    programs in Python, (1) a signal might be delivered
    to any thread (which is just a malfeature) and (2) if
    the thread that gets the signal is waiting, the signal
    is ignored (which is a bug).

    The watcher is a concurrent process (not thread) that
    waits for a signal and the process that contains the
    threads.  See Appendix A of The Little Book of Semaphores.
    http://greenteapress.com/semaphores/

    I have only tested this on Linux.  I would expect it to
    work on the Macintosh and not work on Windows.

    Refer to: http://code.activestate.com/recipes/496735-workaround-for-missed-sigint-in-multithreaded-prog/
    """

    def __init__(self):
        """ Creates a child thread, which returns.  The parent
            thread waits for a KeyboardInterrupt and then kills
            the child thread.
        """
        self.child = os.fork()
        if self.child == 0:
            return
        else:
            self.watch()

    def watch(self):
        try:
            os.wait()
        except KeyboardInterrupt:
            # I put the capital B in KeyBoardInterrupt so I can
            # tell when the Watcher gets the SIGINT
            print("KeyBoardInterrupt")
            self.kill()
        sys.exit()

    def kill(self):
        try:
            os.kill(self.child, signal.SIGKILL)
        except OSError:
            pass


def killProcTree(pid=None, including_parent=True):
    if not pid:
        # kill the process itself
        pid = os.getpid()
    parent = psutil.Process(pid)
    children = parent.children(recursive=True)
    for child in children:
        child.kill()
    psutil.wait_procs(children, timeout=5)
    if including_parent:
        parent.kill()
        parent.wait(5)
