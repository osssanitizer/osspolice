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

"""
Helper functions
"""
def is_exe(fpath):
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

def is_ascii(s):
    return all(ord(c) < 128 and ord(c) > 20 for c in s)

def md5_digest(s):
    import hashlib
    return hashlib.md5(s.encode('utf-8')).digest()

def md5_digest_int(s):
    import hashlib
    return int(hashlib.md5(s.encode('utf-8')).hexdigest(), 16)

def md5_digest_str(s):
    import binascii
    return binascii.hexlify(md5_digest(s))

def md5_digest_last_64bits(s):
    return md5_digest(s)[:8]

def md5_digest_last_64bits_str(s):
    return md5_digest_str(s)[:16]

def md5_digest_last_64bits_int(s):
    return int(md5_digest_last_64bits_str(s), 16)


"""
Utilities for file system
"""
def list_recursive(indir, prefix=None, suffix=None):
    files_to_aggregate = []  # used to record files with distinct URIs
    for dirName, subdirList, fileList in os.walk(indir):
        for fname in fileList:
            filepath = os.path.join(dirName, fname)
            if prefix and fname.startswith(prefix):
                files_to_aggregate.append(filepath)
            elif suffix and fname.endswith(suffix):
                files_to_aggregate.append(filepath)
            elif not prefix and not suffix:
                files_to_aggregate.append(filepath)
    return files_to_aggregate

def list_recursive_unique_filename(indir, prefix=None, suffix=None):
    fname2filepath = {}  # used to record files with distinct filenames
    for dirName, subdirList, fileList in os.walk(indir):
        for fname in fileList:
            filepath = os.path.join(dirName, fname)
            if prefix and fname.startswith(prefix):
                fname2filepath[fname] = filepath
            if suffix and fname.endswith(suffix):
                fname2filepath[fname] = filepath
            elif not prefix and not suffix:
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
    exclude_filename = os.path.join( log_dir, '%s-%s-%s' % (prefix, job, inname) )
    return exclude_filename


def getExcludeList(infile):
    # the exclude file is stored as ./log/exclude-$job_name-$infile_md5
    exclude_filename = getExcludeFilename(infile)
    if os.path.exists(exclude_filename):
        return filter(bool, open(exclude_filename, 'r').read().split('\n'))
    else:
        return []


"""
Utilities for protocol buffer IO
"""
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


"""
Utilities for multithreading
"""
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
        except OSError: pass


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


###########################################################
# ProgressBar
###########################################################
import progressbar
class Progressbar:
	def __init__(self, msg, maxval):
		try:
			#see docs for other options
			self.__widgets = [msg, progressbar.Percentage(), \
							' ', progressbar.Bar(marker='#', \
							left='[',right=']'),
							' ', progressbar.ETA(), ' ', \
							progressbar.FileTransferSpeed()]

			self.__bar = progressbar.ProgressBar(maxval=maxval, widgets=self.__widgets)
		except Exception as e:
			raise Exception("Failed to init progressbar: " + str(e))

	def start(self):
		if self.__bar:
			self.__bar.start()
		else:
			raise Exception("Progressbar not created")

	def msg(self, msg):
		if self.__widgets:
			self.__widgets[0] = msg

	def update(self, count):
		if self.__bar:
			self.__bar.update(count)
		else:
			raise Exception("Progressbar not created")

	def finish(self):
		if self.__bar:
			self.__bar.finish()
		else:
			raise Exception("Progressbar not created")


