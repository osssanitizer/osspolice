# Build gtags with --with-sqlite3, to enable output of sqlite3 format.
import sqlite3
import subprocess
import os
import sys
from os.path import join, realpath, abspath, dirname, relpath
from collections import Counter

class ParserOutput(object):
    # Introduction to library functions
    # http://man7.org/linux/man-pages/man3/intro.3.html
    DEF = 'GTAGS'
    REF = 'GRTAGS'
    PATH = 'GPATH'
    CMD = 'gtags'

    REALPATH = realpath(__file__)
    REALDIR = dirname(REALPATH)
    DIE_POSIX = join(REALDIR, 'data/posix.die.txt')
    MAN7_POSIX = join(REALDIR, 'data/posix.man7.txt')
    DIE_SYSCALL = join(REALDIR, 'data/syscall.die.txt')
    MAN7_SYSCALL = join(REALDIR, 'data/syscall.man7.txt')
    TABLE_NAME = 'db'

    def __init__(self, repo_dir, store_dir=None, source='man7'):  # source can be 'die' or 'man7', man7 seems better
        # Invoke gtags
        cur_dir = os.getcwd()
        os.chdir(repo_dir)
        if store_dir:
            ret = subprocess.call([self.CMD, '--sqlite3', store_dir])  # GTAGS, GRTAGS, GPATH are created in store_dir
        else:
            ret = subprocess.call([self.CMD, '--sqlite3'])  # GTAGS, GRTAGS, GPATH are created in repo_dir
        os.chdir(cur_dir)
        if not ret == 0:
            raise Exception("gtags fails in %s" % repo_dir)
        self.def_db = sqlite3.connect(join(repo_dir, self.DEF))
        self.ref_db = sqlite3.connect(join(repo_dir, self.REF))
        self.path_db = sqlite3.connect(join(repo_dir, self.PATH))
        cur = self.def_db.cursor()
        cur.execute('SELECT key, dat, extra FROM %s WHERE extra IS NOT NULL' % self.TABLE_NAME)
        def_results = cur.fetchall()
        self.all_defs = [{'key': key[0], 'dat': key[1], 'path': key[2]} for key in def_results]
        cur = self.ref_db.cursor()
        cur.execute('SELECT key, extra FROM %s WHERE extra IS NOT NULL' % self.TABLE_NAME)
        ref_results = cur.fetchall()
        self.all_refs = [{'key': key[0], 'path': key[1]} for key in ref_results]
        cur = self.path_db.cursor()
        cur.execute('SELECT key, dat FROM %s WHERE extra IS NULL' % self.TABLE_NAME)
        path_mappings = cur.fetchall()
        # The selected result contains, both path_id->filepath, and filepath->path_id, we only need the path_id->filepath
        self.path_mappings = {key[0]: key[1] for key in path_mappings if key[0].encode('utf8').isdigit()}

        if source == 'die':
            self.posix_set = self._load_callset_from_file(self.DIE_POSIX)
            self.syscall_set = self._load_callset_from_file(self.DIE_SYSCALL)
        elif source == 'man7':
            self.posix_set = self._load_callset_from_file(self.MAN7_POSIX)
            self.syscall_set = self._load_callset_from_file(self.MAN7_SYSCALL)
        else:
            # Maybe add a union?
            raise Exception("Unknown source type!")

    def __del__(self):
        # TODO: should I remove the tags file?
        pass

    @staticmethod
    def _load_callset_from_file(filename):
        return set([line.split('(')[0] for line in open(filename, 'r').read().split('\n')])

    def is_syscall(self, func_name):
        return func_name in self.syscall_set

    def is_posix(self, func_name):
        return func_name in self.posix_set

    def get_system_calls(self):
        # Generate syscall -> number of references
        # system call list
        # http://linux.die.net/man/2/
        # or
        # http://man7.org/linux/man-pages/dir_section_2.html
        all_syscalls = [ele['key'] for ele in self.all_refs]  # 'key': key, 'path': path
        all_syscalls_dict = Counter(all_syscalls)
        syscall_keys = set(all_syscalls_dict) & self.syscall_set
        return {key: all_syscalls_dict[key] for key in syscall_keys}

    def get_posix_calls(self):
        # Generates posixcall -> number of references
        # libc (posix?) calls
        # http://linux.die.net/man/3/
        # or
        # http://man7.org/linux/man-pages/dir_section_3.html
        all_posixcalls = [ele['key'] for ele in self.all_refs]  # 'key': key, 'path': path
        all_posixcalls_dict = Counter(all_posixcalls)
        posix_keys = set(all_posixcalls_dict) & self.posix_set
        return {key: all_posixcalls_dict[key] for key in posix_keys}

    def is_call(self, call_desc, only_export=False, conservative=False):
        # TODO: this is very ad-hoc now, and doesn't really work for classes, because the descriptor may not be available
        key = call_desc['key']
        dat = call_desc['dat']
        if conservative:
            if not ('class' in dat or 'enum' in dat or '#@d' in dat or '@t' in dat):
                if only_export:
                    if 'static' in dat or 'private' in dat:
                        return False
                    else:
                        return True
                else:
                    return True
        else:
            if '(' in dat: #and ')' in dat:
                if only_export:
                    if 'static' in dat or 'private' in dat:  # classes may not explicitly say private
                        return False
                    else:
                        return True
                else:
                    return True

    def get_export_calls(self):
        # non static, non private functions
        # is function, static, not private
        return [call_desc for call_desc in self.all_defs if self.is_call(call_desc=call_desc, only_export=True)]

    def get_all_calls(self):
        return [call_desc for call_desc in self.all_defs if self.is_call(call_desc=call_desc)]

    def get_file_call_mappings(self):
        # generate filepath to call mappings, i.e. filepath -> {'system_call': [], 'posix_call': [], 'exported_function':[]}
        filepath_call_mappings = {}
        for call_desc in self.all_defs:
            if self.is_call(call_desc=call_desc, only_export=True):
                # Exported functions
                filepath = self.path_mappings[call_desc['path']]
                filepath_call_mappings.setdefault(filepath, {}).setdefault('exported_function', []).append(call_desc['key'])
        for call_desc in self.all_refs:
            if call_desc['key'] in self.syscall_set:
                filepath = self.path_mappings[call_desc['path']]
                filepath_call_mappings.setdefault(filepath, {}).setdefault('system_call', []).append(call_desc['key'])
            elif call_desc['key'] in self.posix_set:
                filepath = self.path_mappings[call_desc['path']]
                filepath_call_mappings.setdefault(filepath, {}).setdefault('posix_call', []).append(call_desc['key'])
            else:
                pass
        return filepath_call_mappings


if __name__=="__main__":
    if len(sys.argv) == 2:
        repo_dir = sys.argv[1]
    else:
        repo_dir = './testdata/'
    parser = ParserOutput(repo_dir)
    print ("sys calls")
    print (parser.get_system_calls())
    print ("posix calls")
    print (parser.get_posix_calls())
    print ("all defined calls")
    all_calls = [call_desc['key'] for call_desc in parser.get_all_calls()]
    print (all_calls)
    print ("all defined & exported calls")
    exported_calls = [call_desc['key'] for call_desc in parser.get_export_calls()]
    print (exported_calls)
