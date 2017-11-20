# Exctract routine signatures from a C++ module
import re
import sys
import os
import utils
from simhash import Simhash
from itertools import groupby


def is_ascii(s):
    return all(ord(c) < 128 and ord(c) > 20 for c in s)


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


def loadtxt(filename):
    "Load text file into a string. I let FILE exceptions to pass."
    f = open(filename)
    txt = ''.join(f.readlines())
    f.close()
    return txt


def extract_functions_regex(file_path, exported_only=False):
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


def hashfunc(x):
    # do nothing
    return int(x.decode('utf-8'))  # int(x, 16)


def simhash(x):
    try:
        return Simhash(x, hashfunc=hashfunc)
    except Exception as e:
        print "Failed to get simhash: %s" % (str(e))
        return None


def get_simhash_distance(h1, h2):
    sh1 = simhash(long(h1))
    sh2 = simhash(long(h2))
    if sh1 and sh2:
        return sh1.distance(sh2)
    return -1


def get_simhash(items):
    if not items or not len(items):
        return None
    else:
        items = {str(key): val for key, val in items.items()}
        sh = simhash(items)
        if sh:
            return sh.value
        print "failed to get simhash!"
        return None


def is_src_file(filename, extensions=['.h', '.c', '.cc', '.cpp']):
    return any(filename.endswith(e) for e in extensions)


def get_src_files(repo_path):
    """
    Function to build a list of all files with an extension in @ext
    """
    try:
        tree = {}
        for root, dirs, files in os.walk(repo_path):
            for filename in filter(is_src_file, files):
                path = os.path.join(root, filename)
                if os.path.isfile(path) and not os.path.islink(path):
                    yield root, path
    except Exception as e:
        print "Error retrieving source files in %s: %s" % (repo_path, str(e))


###########################################################
# String processor
###########################################################

def dir_simhash(path):
    strings = {}
    functions = {}

    for dir_path, file_path in get_src_files(path):
        for string in extract_strings_regex(file_path):
            if not string or len(string) < 3 or \
                    not utils.is_ascii(string):
                continue

            if string:
                if not file_path in strings:
                    strings[file_path] = {}
                str_id = utils.md5_digest_int("str-" + string)
                if not str_id in strings[file_path]:
                    strings[file_path][str_id] = 1
                else:
                    strings[file_path][str_id] += 1

        for func in extract_functions_regex(file_path):
            if func:
                if not file_path in functions:
                    functions[file_path] = {}
                func_id = utils.md5_digest_int("func-" + func)
                if not func_id in functions[file_path]:
                    functions[file_path][func_id] = 1
                else:
                    functions[file_path][func_id] += 1

        total = {}
        total_strings = {}
        total_functions = {}
        if file_path in strings:
            total_strings.update(strings[file_path])
            total.update(strings[file_path])
        if file_path in functions:
            total_functions.update(functions[file_path])
            total.update(functions[file_path])

        # if len(total):
        #	print file_path, get_simhash(total),
        #	print " strings: " + str(len(total_strings)) + \
        #			" functions: " + str(len(total_functions))

    total = {}
    total_strings = {}
    total_functions = {}
    for l in strings.values():
        total_strings.update(l)
        total.update(l)
    for l in functions.values():
        total_functions.update(l)
        total.update(l)

    sh = get_simhash(total)
    # print "total strings: " + str(len(total_strings)) + " functions: " + str(len(total_functions))
    # print sh
    return sh


if __name__ == "__main__":
    for s in extract_strings_regex(sys.argv[1]):
        print s
    # s1 = dir_simhash(sys.argv[1])
    # s2 = dir_simhash(sys.argv[2])
    # print get_simhash_distance(s1, s2)
