import subprocess
import sys
import os
import json
from ctypes import *
from os import walk
from os.path import join, realpath, dirname, splitext

realdir = dirname(realpath(__file__))
lib = cdll.LoadLibrary(join(realdir, 'LexerParser.so'))

# void* CreateFeatureGroups(const char *)
lib.CreateFeatureGroups.restype = c_void_p
lib.CreateFeatureGroups.argtypes = [c_char_p, c_char_p, c_int, c_char_p]

# const char ** GetFeatures(void *, int)
lib.GetFeatures.restype = POINTER(c_char_p)
lib.GetFeatures.argtypes = [c_void_p, c_int, c_int, c_int]

class FeatureFlags:
    NONE = 0
    GROUP = 1
    EXPORT_TYPE = 2
    LOCATION = 4

class FeatureType:
    STRINGS= 1
    FUNCTIONS = 2
    VARIABLES = 4
    SYSCALLS = 8
    POSIX_CALLS = 16
    ALL = -1

class FunctionType:
    EXPORT_FUNCTION = 1
    MEMBER_FUNCTION = 2
    TEMPLATE_SPECIALIZATION = 4
    TEMPLATE_MEMBER_SPECIALIZATION = 8
    TEMPLATE_FUNCTION = 16
    USED_FUNCTION = 32

def CreateFeatureGroups(infile, rootdir, mode=1, tag=None):
    """
    Args:
        infile: the file to analyze
        rootdir: the root path of the repo, used for header
        mode: 0/1 lexer/parser
    Returns:
        result: groups
    """
    infile = create_string_buffer(infile)
    rootdir = create_string_buffer(rootdir)
    mode = c_int(mode)
    return lib.CreateFeatureGroups(infile, rootdir, mode, tag)

def GetFeatureGroups(infile, rootdir, mode=1, tag=None):
    print "Parsing ", infile
    # create groups
    groups = CreateFeatureGroups(infile, rootdir, mode, tag)
    # failed to get groups
    if not groups:
        print "failed to create groups"
        return None
    else:
        return groups

def GetFeatures(groups, typ=FeatureType.ALL, flags=FeatureFlags.NONE):
    # failed to get groups
    if not groups:
        print "failed to create groups"
        return

    # config
    # 0 means the first group, -1 means all group (slow)
    #grpNum = 0
    grpNum = -1

    #typ = FeatureType.STRINGS
    #typ = FeatureType.FUNCTIONS
    #typ = FeatureType.ALL

    #flags = FeatureFlags.NONE
    #flags = FeatureFlags.GROUP | FeatureFlags.LOCATION

    # get features now
    features = lib.GetFeatures(groups, typ, flags, grpNum)
    for feature in features:

        # list ends when None found
        if not feature:
            break

        # process this feature
        yield feature

def str2bool(v):
    return v.lower() in ("yes", "true", "t", "1")

def update_features(path2features, filepath, features, flags=FeatureFlags.NONE):
    # flags = 0, typ:feat
    # flags = 1, typ:grp:feat
    # flags = 2, typ:export:feat
    # flags = 4, typ:start_row:start_col:end_row:end_col:feat
    # flags = 7, typ:grp:export:start_row:start_col:end_row:end_col:feat
    # if parsing fails!
    if features is None:
        path2features[filepath] = None
        return

    # add features to path2features mapping
    path2features.setdefault(filepath, {})
    path2features[filepath].setdefault('string_literal', [])
    path2features[filepath].setdefault('exported_function', [])
    path2features[filepath].setdefault('exported_function_name', [])
    path2features[filepath].setdefault('variable', [])
    path2features[filepath].setdefault('system_call', [])
    path2features[filepath].setdefault('posix_call', [])
    for feature in features:
        typ, feature = feature.split(':', 1)
        if flags & FeatureFlags.GROUP:
            grp, feature = feature.split(':', 1)
        if flags & FeatureFlags.EXPORT_TYPE:
            exp, feature = feature.split(':', 1)
        if flags & FeatureFlags.LOCATION:
            start_row, start_col, end_row, end_col, feature = feature.split(':', 4)
        if typ == 's':
            feature = feature[1:-1]  # get rid of quotes
        if flags != FeatureFlags.NONE:
            feature = [feature]
            if flags & FeatureFlags.GROUP:
                feature += [int(grp)]
            if flags & FeatureFlags.EXPORT_TYPE:
                feature += [int(exp)]
            if flags & FeatureFlags.LOCATION:
                feature += [int(start_row), int(start_col), int(end_row), int(end_col)]
        if typ == 's':
            path2features[filepath]['string_literal'].append(feature)
        elif typ == 'f':
            path2features[filepath]['exported_function'].append(feature)
        elif typ == 'fn':
            path2features[filepath]['exported_function_name'].append(feature)
        elif typ == 'v':
            path2features[filepath]['variable'].append(feature)

def LexerParser(arg, rootdir, mode=1, flags=FeatureFlags.NONE, tag=None):
    """This method generates the signatures for each file in @arg.

    :param arg: input directory
    :return: path -> {string_literals, exported_functions, exported_function_names} mapping
    """
    filepath_to_features = {}
    # First, run the Lexer on all the C files and CPP files
    c_suffix = set(['.c', '.h'])
    cpp_suffix = set(['.c++', '.cc', '.hh', '.cpp', '.cxx', '.hxx', '.hpp', '.C', '.H'])
    exclude = set(['.git'])

    if os.path.isdir(arg) and os.path.exists(arg):

        for root, dirs, files in walk(arg, topdown=True):

            # http://stackoverflow.com/questions/19859840/excluding-directories-in-os-walk
            dirs[:] = [d for d in dirs if d not in exclude]
            for fname in files:

                # callLexerParser outputs mapping from tokType to tokens
                extension = splitext(fname)[-1]

                if extension in c_suffix or extension in cpp_suffix:
                    filepath = join(root, fname)
                    groups = GetFeatureGroups(infile=filepath, rootdir=rootdir, mode=mode, tag=tag)
                    if groups:
                        features = list(GetFeatures(groups=groups, typ=FeatureType.ALL, flags=flags))
                    else:
                        features = None
                    update_features(path2features=filepath_to_features, filepath=filepath, features=features, flags=flags)

        return filepath_to_features

    elif os.path.isfile(arg) and os.path.exists(arg):

        # callLexerParser outputs mapping from tokType to tokens
        extension = splitext(arg)[-1]

        if extension in c_suffix or extension in cpp_suffix:
            groups = GetFeatureGroups(infile=arg, rootdir=rootdir, mode=mode, tag=tag)
            if groups:
                features = list(GetFeatures(groups=groups, typ=FeatureType.ALL, flags=flags))
            else:
                features = None
            update_features(path2features=filepath_to_features, filepath=arg, features=features, flags=flags)
            return filepath_to_features

if __name__=="__main__":
    if len(sys.argv) == 3:
        for filepath, features in LexerParser(sys.argv[1], sys.argv[2]).items():
            if filepath:
                if features is None:
                    print ("Parsing File: %s failed!" % filepath)
                else:
                    print ("Parsing File: %s success, features are %s!" % (filepath, features))
    elif len(sys.argv) == 4:
        for filepath, features in LexerParser(sys.argv[1], sys.argv[2], mode=int(sys.argv[3])).items():
            if filepath:
                if features is None:
                    print ("Parsing File: %s failed!" % filepath)
                else:
                    print ("Parsing File: %s success, features are %s!" % (filepath, features))
    elif len(sys.argv) >= 5 and len(sys.argv) <= 7:
        outfile = sys.argv[4]
        # parse the flags parameter
        if len(sys.argv) >= 6:
            flags = int(sys.argv[5])
        else:
            flags = FeatureFlags.NONE  # 0
        # parse the tag parameter
        if len(sys.argv) >= 7:
            tag = sys.argv[6]
        else:
            tag = None
        filepath_to_features = LexerParser(sys.argv[1], sys.argv[2], mode=int(sys.argv[3]), flags=flags, tag=tag)
        outf = open(outfile, 'w')
        # fix non ascii code
        json.dump(filepath_to_features, outf, ensure_ascii=False)
        outf.close()

    else:
        raise Exception('Usage: python LexerParserWrapper.py $path-to-a-file-or-dir $root-dir [$mode $outfile $flags(0|1|2|4|3|7) $tag]')

