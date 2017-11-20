# The Lexer and Parser
import sys
from LexerOutputWrapper import callLexerOutput
from ParserOutputWrapper import ParserOutput
from os import walk
from os.path import join, relpath, splitext

def LexerParser(indir):
    """This method generates the signatures for each critical file in the indir.

    :param indir: input directory
    :return: path -> {string_literal, posix_call, system_call, exported_function} mapping
    """
    filepath_to_features = {}
    # First, run the Lexer on all the C files and CPP files
    c_suffix = set(['.c', '.h'])
    cpp_suffix = set(['.c++', '.cc', '.hh', '.cpp', '.cxx', '.hxx', '.hpp', '.C', '.H'])
    exclude = set(['.git', 'bin'])
    for root, dirs, files in walk(indir, topdown=True):
        # http://stackoverflow.com/questions/19859840/excluding-directories-in-os-walk
        dirs[:] = [d for d in dirs if d not in exclude]
        for fname in files:
            # callLexerOutput outputs mapping from tokType to tokens
            extension = splitext(fname)[-1]
            if extension in c_suffix or extension in cpp_suffix:
                filepath = join(root, fname)
                string_literals = list(callLexerOutput(infile=filepath, filterTokenTypes='string_literal'))
                rel_filepath = './%s' % relpath(filepath, indir)
                filepath_to_features.setdefault(rel_filepath, {})['string_literal'] = string_literals
    # Second, run the Parser on all the source code.
    # TODO: by default, GTAGS runs parser on C, C++, yacc, Assembly, Java, PHP, we should only point to C/C++
    parser_obj = ParserOutput(repo_dir=indir, source='man7')
    for filepath, summary in parser_obj.get_file_call_mappings().items():
        filepath_to_features.setdefault(filepath, {})['system_call'] = summary['system_call'] if 'system_call' in summary else []
        filepath_to_features.setdefault(filepath, {})['posix_call'] = summary['posix_call'] if 'posix_call' in summary else []
        filepath_to_features.setdefault(filepath, {})['exported_function'] = summary['exported_function'] if 'exported_function' in summary else []
    return filepath_to_features

if __name__=="__main__":
    if len(sys.argv) == 2:
        for filepath, features in LexerParser(sys.argv[1]).items():
            print (filepath, features)
    else:
        raise Exception('Usage: python LexerParser.py $indir')

