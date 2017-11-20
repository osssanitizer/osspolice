#!/usr/bin/python

import sys
import os
import shutil
import subprocess
from contextlib import contextmanager

###########################################################
# Helper functions
###########################################################
def chunks(l, n):
    """Yield successive n-sized chunks from l"""
    for i in range(0, len(l), n):
        yield l[i:i + n]

def percentage(part, whole):
    return round(((float(part)*100)/float(whole)), 2)

def num_digits(num):
    import math
    return int(math.log10(num))+1

def fraction(part, whole):
    return int((int(part) * int(whole)) / 100)

def in_range(start, end, step):
    while start <= end:
        yield start
        start += step

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

# computes "term frequency" which is the number of times a string appears in a repo, and normalize it by a norm_term
def tf(freq, norm_term):
    try:
        return (float(freq) / norm_term)
    except Exception as e:
        raise Exception("tf failed: " + str(e))

#
# computes "inverse document frequency" which measures how
# common a string is among all repos
#
def idf(total, matching):
    try:
        import math
        return math.log(float(total) / (1 + matching))
    except Exception as e:
        raise Exception("idf failed: " + str(e))

# computes the TF-IDF score: product of tf and idf.
def tfidf(tf_val, idf_val):
    try:
        return (tf_val * idf_val)
    except Exception as e:
        raise Exception("tfidf failed: " + str(e))

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

###########################################################
# Signal Handling
###########################################################
import signal
class Signal:
    SIGINT = signal.SIGINT
    SIGTERM = signal.SIGTERM

    def __init__(self):
        self.__caught = dict()

    def install(self, siglist):
        for signum in siglist:
            self.__caught[signum] = False
            signal.signal(signum, self.__handler)

    def __handler(self, signum, frame):
        self.__caught[signum] = True

    def caught(self, signum=None):
        if signum:
            if signum in self.__caught:
                return self.__caught[signum]
            else:
                return False

        for signum in self.__caught.keys():
            if self.__caught[signum]:
                return True

        return False

class TimeoutException(Exception): pass

@contextmanager
def time_limit(seconds):
    def signal_handler(signum, frame):
        raise TimeoutException, "Timed out!"
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
