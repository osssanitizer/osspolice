import json
import sys

libs = json.load(open(sys.argv[1], 'r'))
outf = open("lib_id.txt", 'w')
for key, values in libs.items():
    if type(values) == str or type(values) == unicode:
        continue

    if type(values) == list:
        if len(values) == 1:
            continue
        outf.write('\n'.join(values[1:]) + '\n')

outf.close()
