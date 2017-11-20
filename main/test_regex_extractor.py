import sys, os, re


def loadtxt(file_path):
    f = open(file_path)
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
    rproc += "(<.*>)?"  # optional template
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


if __name__ == "__main__":
    for s in extract_functions_regex(sys.argv[1]):
        print s
