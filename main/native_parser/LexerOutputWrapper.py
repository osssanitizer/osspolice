import subprocess
import sys
import os
from os.path import realpath, dirname, join
from ctypes import *

realdir = dirname(realpath(__file__))
lib = cdll.LoadLibrary(join(realdir, 'LexerOutput.so'))
lib.NextLexerOutput.restype = c_char_p
lib.NextLexerOutput.argtypes = [c_char_p, c_int, POINTER(POINTER(c_char))]


def callLexerOutput(infile, filterTokenTypes=None, disableIfDef=False, disableInclude=False):
    """
    Args:
        infile: the file to analyze
        filterTokenTypes: only output the specified TokenTypes, default None
    Returns:
        result: list of strings, the lexer output
    """
    infile = create_string_buffer(infile)
    pointers = None
    if filterTokenTypes:
        pointers = (POINTER(c_char) * (len(filterTokenTypes) + 1))()
        for idx, tokenType in enumerate(filterTokenTypes):
            pointers[idx] = create_string_buffer(tokenType)
    while True:
        temp = lib.NextLexerOutput(infile, len(filterTokenTypes), pointers, disableIfDef, disableInclude)
        if not temp:
            break
        infile = None
        yield temp

def callLexerOutputSubprocess(infile, filterTokenTypes=None, disableIfDef=False, disableInclude=False):
    # deprecated. used subprocess and is inefficient
    results = subprocess.check_output(['./LexerOutput', infile, filterTokenTypes, \
                                       disableIfDef, disableInclude], \
                                       stdout=subprocess.STDOUT, \
                                       stderr=subprocess.STDERR)
    lexerLines = [line.split(':', 1) for line in results.split(os.linesep)]
    lexerDict = {}
    for typeValue in lexerLines:
        if len(typeValue) != 2:
            continue
        tokType, tokValue = typeValue
        if filterTokenTypes and tokType != filterTokenTypes:
            continue
        tokValue = tokValue.strip('\'')  # Is this correct?
        lexerDict.setdefault(tokType, []).append(tokValue)
    return lexerDict

def str2bool(v):
    return v.lower() in ("yes", "true", "t", "1")

if __name__=='__main__':
    if len(sys.argv) == 2:
        for item in callLexerOutput(sys.argv[1]):
            print(item)
    elif len(sys.argv) == 3:
        filterTokenTypes = sys.argv[2].split(' ')
        for item in callLexerOutput(sys.argv[1], filterTokenTypes=filterTokenTypes):
            print(item)
    elif len(sys.argv) == 4:
        filterTokenTypes = sys.argv[2].split(' ')
        for item in callLexerOutput(sys.argv[1], filterTokenTypes=filterTokenTypes, \
                                    disableIfDef=str2bool(sys.argv[3])):
            print(item)
    elif len(sys.argv) == 5:
        filterTokenTypes = sys.argv[2].split(' ')
        for item in callLexerOutput(sys.argv[1], filterTokenTypes=filterTokenTypes, \
                                    disableIfDef=str2bool(sys.argv[3]), \
                                    disableInclude=str2bool(sys.argv[3])):
            print(item)
    else:
        raise Exception('Usage: python LexerOutputWrapper.py $infile [$filterTokenTypes]')
