#!/usr/bin/python
import os
import sys

def gen_clang_parser_include(basedir, outfile=None, recursive=False, relpath=True):
    # traverse root directory, and list directories as dirs and files as files
    include_files = []
    if recursive:
        for root, dirs, files in os.walk(basedir):
            for fname in files:
                if relpath:
                    include_files.append(fname)
                else:
                    include_files.append(os.path.join(root, fname))
    else:
        for fname in os.listdir(basedir):
            fullpath = os.path.join(basedir, fname)
            if os.path.isfile(fullpath):
                if relpath:
                    include_files.append(fname)
                else:
                    include_files.append(fullpath)
    if not outfile:
        outfile = './clang_parser_include.h'
    include_files = ['#include<%s>' % fname for fname in include_files]
    open(outfile, 'w').write('\n'.join(include_files))

if __name__ == "__main__":
    if (len(sys.argv) < 2) or (len(sys.argv) > 4):
        raise Exception("Usage: python gen_clang_parser_include.py $include_path "
                        "[$outfile (default 'clang_parser_include.h') $recursive]\n")

    if len(sys.argv) == 2:
        gen_clang_parser_include(basedir=sys.argv[1])
    elif len(sys.argv) == 3:
        gen_clang_parser_include(basedir=sys.argv[1], outfile=sys.argv[2])
    elif len(sys.argv) == 4:
        gen_clang_parser_include(basedir=sys.argv[1], outfile=sys.argv[2], recursive=True)
    else:
        raise Exception("Incorrect number of arguments!")
