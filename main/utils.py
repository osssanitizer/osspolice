#!/usr/bin/python
import os
import signal
import progressbar
import numpy as np
from contextlib import contextmanager
from simhash import Simhash
from itertools import product, combinations


###########################################################
# Helper functions
###########################################################
def any_and_return(test_fields, target_fields):
    for test_field in test_fields:
        if test_field in target_fields:
            return test_field
    return None


def repo_scanned(redis, repo_id, logger=None):
    try:
        exists = redis.exists(repo_id)
        if exists:
            logger.debug("repo %s already indexed", repo_id)
            return True
        return False

    except Exception as e:
        logger.error("repo_scanned: error %s", str(e))
        return False


def which(program):
    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None


def ts_from_date(d):
    import calendar
    return calendar.timegm(d.timetuple())


def ts_to_date_str(ts, fmt='%Y-%m-%d %H:%M:%S.%f'):
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime(fmt)


def ts_now_str(fmt='%Y-%m-%d %H:%M:%S.%f'):
    import datetime
    return datetime.datetime.now().strftime(fmt)


def ts_to_date(ts):
    import datetime
    return datetime.datetime.fromtimestamp(ts)


def get_git_log(repo_dir, fmt='--pretty=%ct', count=1):
    import git
    exe = which("git")
    if not exe:
        raise Exception("git executable not found")
    repo = git.Git(repo_dir)
    return repo.log(fmt, '-n', count)


def checkout_git_tag(repo_dir, tag):
    import git
    exe = which("git")
    if not exe:
        raise Exception("git executable not found")
    repo = git.Git(repo_dir)
    try:
        repo.checkout(tag)
    except Exception as e:
        print ("failed to checkout tag %s of repo %s, error is %s" % (tag, repo_dir, str(e)))
        return False
    return True


def chunks(l, n):
    """Yield successive n-sized chunks from l"""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def percentage(part, whole):
    return round(((float(part) * 100) / float(whole)), 2)


def num_digits(num):
    import math
    return int(math.log10(num)) + 1


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
    try:
        return hashlib.md5(s.encode('utf-8')).digest()
    except:
        return hashlib.md5(s).digest()


def md5_digest_int(s):
    import hashlib
    try:
        return int(hashlib.md5(s.encode('utf-8')).hexdigest(), 16)
    except:
        return int(hashlib.md5(s).hexdigest(), 16)


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


# computes "inverse document frequency" which measures how common a string is among all repos
def idf(total, matching):
    try:
        import math
        return math.log(float(total) / (1 + matching))
    except Exception as e:
        raise Exception("idf failed: " + str(e))


# computes the TF-IDF score: product of tf and idf.
def tfidf(tf_val, idf_val):
    try:
        return tf_val * idf_val
    except Exception as e:
        raise Exception("tfidf failed: " + str(e))


###########################################################
# ProgressBar
###########################################################
class Progressbar:
    def __init__(self, msg, maxval):
        try:
            # see docs for other options
            self.__widgets = [msg, progressbar.Percentage(),
                              ' ', progressbar.Bar(marker='#', left='[', right=']'),
                              ' ', progressbar.ETA(), ' ', progressbar.FileTransferSpeed()]

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


class TimeoutException(Exception):
    pass


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


###########################################################
# Similarity calculation
###########################################################
def hashfunc(x):
    # do nothing
    return int(x.decode('utf-8'))  # int(x, 16)


def simhash(x, logger=None):
    try:
        return Simhash(x, hashfunc=hashfunc)
    except Exception as e:
        if logger:
            logger.error("Failed to get simhash: %s", str(e))
        return None


def get_simhash_distance(h1, h2):
    sh1 = simhash(long(h1))
    sh2 = simhash(long(h2))
    if sh1 and sh2:
        return sh1.distance(sh2)
    return -1


def get_simhash(items, logger=None):
    if not items or not len(items):
        return None
    else:
        if isinstance(items, dict):
            items = {str(k): v for k, v in items.items()}
        elif isinstance(items, list):
            items = [str(x) for x in items]
        else:
            if logger:
                logger.error("failed to get simhash. invalid type %s", type(items))
        sh = simhash(items)
        if sh:
            return sh.value
        if logger:
            logger.error("failed to get simhash")
        return None


def get_key(main, string):
    if main.USE_MD5_64BITS:
        if main.USE_MD5_INT:
            key = md5_digest_last_64bits_int(string)

        elif main.USE_SHORT_STRS_AS_KEYS:
            if len(string) > 8:
                key = md5_digest_last_64bits_str(string)
            else:
                key = string
        else:
            key = md5_digest_last_64bits_str(string)
    else:
        if main.USE_MD5_INT:
            key = md5_digest_int(string)

        elif main.USE_SHORT_STRS_AS_KEYS:
            if len(string) > 8:
                key = md5_digest_str(string)
            else:
                key = string
        else:
            key = md5_digest_str(string)

    return key


def get_node_id(main, features, algorithm=None, logger=None):
    if not algorithm:
        algorithm = main.NODE_ID_ALGORITHM

    try:
        features = [get_key(main, unicode(feature, errors='ignore')) for feature in features]

        if algorithm == 'simhash':
            return get_simhash(features)
        elif algorithm == 'md5':
            features = [str(feat) for feat in features]
            sorted_features_str = ','.join(sorted(features))
            return md5_digest_int(sorted_features_str)
        elif algorithm == 'sha1':
            raise Exception("Not implemented yet!")
        else:
            if logger:
                logger.error("Unsupported NODE_ID_ALGORITHM: %s", algorithm)

    except Exception as e:
        if logger:
            logger.error("failed to get node id for features %s: %s", features, str(e))
        return None


class SimhashGroup(object):
    def __init__(self, hash_size=64, use_centroid=True):
        self.name2id_value = {}
        self.name2external_value = {}
        self.use_centroid = use_centroid
        self.centroid = np.zeros(hash_size) if self.use_centroid else None
        self.values_sum = 0

    def node_names(self):
        return self.name2id_value.keys()

    def get_size(self):
        return len(self.name2id_value)

    def _get_norm_centroid(self):
        return self.centroid / self.get_size()

    def node_distance(self, node_id):
        """
        ############################################
        example:
        pattern: size = 8, centroid = [1,0,0,5,0,0,0,0, 8,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, ...]
        s: [10000000 10000000 00000000 ...]
        total_dist: 8-1 + 5 + 8-8 = 12
        dist: 12 / 8 = 1.5
        """
        if not self.use_centroid:
            raise Exception("Group not comparable because use_centroid is set to False!")

        total_dist = 0
        base = 1
        for centroid in self.centroid:
            if node_id & base:
                total_dist += self.get_size() - centroid
            else:
                total_dist += centroid
            base = base << 1
        return float(total_dist) / self.get_size()

    def group_distance(self, group):
        if not self.use_centroid:
            raise Exception("Group not comparable because use_centroid is set to False!")

        return sum(abs(self._get_norm_centroid() - group._get_norm_centroid()))

    def is_member(self, node_name):
        return node_name in self.name2id_value

    def add(self, node_name, node_id, node_value, external_value=None):
        # test whether the node exists
        if self.is_member(node_name):
            # maybe the external value needs to be updated!
            self.update_external(node_name=node_name, external_value=external_value)
            return

        # add the node to the internal record
        self.name2id_value[node_name] = (node_id, node_value)
        if external_value is not None:
            self.update_external(node_name=node_name, external_value=external_value)
        else:
            self.update_values_sum()

        # optionally update the centroid
        if self.use_centroid:
            base = 1
            for index in range(len(self.centroid)):
                if node_id & base:
                    self.centroid[index] += 1
                base = base << 1

    def merge(self, group):
        if len(set(self.name2id_value) & set(group.name2id_value)) == 0:
            self.name2id_value.update(group.name2id_value)
            self.name2external_value.update(group.name2external_value)
            if self.use_centroid:
                self.centroid += group.centroid
            self.update_values_sum()
        else:
            for node_name, (node_id, node_value) in group.name2id_value.items():
                ex_value = group.name2external_value[node_name] if node_name in group.name2external_value else None
                self.add(node_name=node_name, node_id=node_id, node_value=node_value, external_value=ex_value)

    def update_external(self, node_name, external_value):
        if not self.is_member(node_name):
            raise Exception("Cannot update external value %s for %s which not in group!", external_value, node_name)
        if external_value is None:
            return
        self.name2external_value[node_name] = external_value
        self.update_values_sum()

    def update_values_sum(self):
        # first element is id, second element is value
        self.values_sum = sum([v for _, v in self.name2id_value.values()]) + sum(self.name2external_value.values())
        return self.values_sum


def update_node2group(node2group, new_node, new_node_refcnt, new_node_external_value=None, search_distance=None):
    new_node_id = int(new_node.split('-', 1)[1])
    if search_distance is None:
        # map every node to its own group!
        node2group.setdefault(new_node, SimhashGroup())
        node2group[new_node].add(node_name=new_node, node_id=new_node_id, node_value=new_node_refcnt,
                                 external_value=new_node_external_value)
    else:
        # compare node with existing groups to figure out group relationship
        if len(node2group) == 0:
            # if there is no groups to compare against
            node2group.setdefault(new_node, SimhashGroup())
            node2group[new_node].add(node_name=new_node, node_id=new_node_id, node_value=new_node_refcnt,
                                     external_value=new_node_external_value)
            return
        else:
            # if there are groups to compare against
            compared_nodes = {new_node}
            existing_nodes = node2group.keys()
            for existing_node in existing_nodes:
                if existing_node in compared_nodes:
                    continue
                existing_node_group = node2group[existing_node]
                if new_node in node2group:
                    if existing_node_group.group_distance(node2group[new_node]) <= search_distance:
                        existing_node_group.merge(node2group[new_node])
                        # only need to update the incoming side, because the hosting side doesn't change!
                        for node_name in node2group[new_node].node_names():
                            node2group[node_name] = existing_node_group
                        compared_nodes.update(existing_node_group.node_names())
                else:
                    if existing_node_group.node_distance(node_id=new_node_id) <= search_distance:
                        existing_node_group.add(node_name=new_node, node_id=new_node_id, node_value=new_node_refcnt,
                                                external_value=new_node_external_value)
                        # only need to update the incoming side, because the hosting side doesn't change!
                        node2group[new_node] = existing_node_group
                        compared_nodes.update(existing_node_group.node_names())

            # if not merged into any group, create a group
            if new_node not in node2group:
                node2group.setdefault(new_node, SimhashGroup())
                node2group[new_node].add(node_name=new_node, node_id=new_node_id, node_value=new_node_refcnt,
                                         external_value=new_node_external_value)


def fix_refcnt(main, feat2refcnt, node2group, matches, level, logger=None):
    """
    Based on the specified SEARCH_SIMHASH_DISTANCE, fix the refcnt for nodes, so that the refcnt reflects popularity.

    :param main: detector object
    :param feat2refcnt: feat -> {'refcnt': X, XX: XX} from java or feat -> {'refcnt': X, 'license': Y, 'filetype': X, XX} for native,
        refcnt values are modified
    :param node2group: node mapped to group and the group's featcnt
    :param matches: the matched parent mapped to its contributing children
    :param level: the matching level, 0 means lookup leaves, 1 means lookup files, 2+ means lookup dirs
    :param logger: the logger instance
    """
    if main.SEARCH_SIMHASH_DISTANCE is None and not main.SEARCH_REFCNT_PROPAGATION:
        return

    # complexity: O(mn), number of new nodes * number of existing nodes!
    if logger:
        logger.info("before update using distance %s, number of eligible nodes is %d, node_groups have %d elements",
                    main.SEARCH_SIMHASH_DISTANCE, len(matches), len(node2group))
    fuzzy_node_types = {'file', 'dir', 'files', 'dirs'}
    for node in matches:
        try:
            # skip unnecessary computation
            if '-' not in node:
                # skip files, dirs etc. which are not typed nodes
                continue
            node_type, _ = node.split('-', 1)
            if node_type not in fuzzy_node_types:
                continue
            if feat2refcnt[node]['featfreq'] == 0:
                continue

            # update the node2group relationship
            refcnt = feat2refcnt[node]['refcnt']
            avg_children_refcnt = None
            if main.SEARCH_REFCNT_PROPAGATION and level >= 1:
                # optionally take the children's refcnt into consideration
                children = matches[node]
                child_refcnt = []
                for child in children:
                    child_refcnt.append(feat2refcnt[child]['refcnt'])
                avg_children_refcnt = np.mean(child_refcnt)
            else:
                if node in node2group:
                    continue
            update_node2group(node2group=node2group, new_node=node, new_node_refcnt=refcnt,
                              new_node_external_value=avg_children_refcnt, search_distance=main.SEARCH_SIMHASH_DISTANCE)
        except Exception as e:
            if logger:
                logger.error("Error updating node groups for node %s: %s", node, str(e))
    if logger:
        logger.info("after update, number of eligible nodes is %d, node_groups have %d elements",
                    len(matches), len(node2group))

    # complexity: O(n)
    updated_feat_set = set()
    for node in matches:
        try:
            if node not in node2group:
                continue
            if node in updated_feat_set:
                continue
            refcnt = feat2refcnt[node]['refcnt']
            if refcnt != node2group[node].values_sum:
                # update all the nodes in the group
                new_refcnt = node2group[node].values_sum
                for group_node in node2group[node].node_names():
                    if logger:
                        logger.debug("updating the refcnt from %d to %d for node %s's group node %s",
                                     refcnt, new_refcnt, node, group_node)
                        feat2refcnt[group_node]['refcnt'] = new_refcnt
                    updated_feat_set.add(group_node)
        except Exception as e:
            if logger:
                logger.error("Error updating feat2refcnt for node %s refcnt %s: %s", node, feat2refcnt[node], str(e))
