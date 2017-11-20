#!/usr/bin/python
import csv
import sys
import os
from random import shuffle


def split_input_list(infile, num_shares, randomize=True):
    reader = csv.DictReader(open(infile, 'r'))
    fieldnames = reader.fieldnames
    rowlist = [row for row in reader]
    shuffle_list = list(rowlist)
    if randomize:
        shuffle(shuffle_list)
    if len(rowlist) <= num_shares:
        raise Exception("There should be more input list (%d) than num_shares (%d)" % (len(rowlist), num_shares))
    share_size = len(rowlist) / num_shares
    for share_id in range(num_shares):
        inname, ext = os.path.splitext(infile)
        share_outfile = inname + '.share-%d' % share_id + ext
        start_index = share_id * share_size

        if share_id < num_shares - 1:
            # The last can be equal to share_size
            end_index = (share_id + 1) * share_size
        else:
            # The last one can be large than share_size
            end_index = max((share_id + 1) * share_size, len(rowlist) + 1)
        share_list = shuffle_list[start_index:end_index]
        writer = csv.DictWriter(open(share_outfile, 'w'), fieldnames=fieldnames)
        writer.writeheader()
        for row in share_list:
            writer.writerow(row)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print ("Usage: %s $input_file $num_of_shares" % sys.argv[0])
        exit(1)

    infile = sys.argv[1]
    num_shares = int(sys.argv[2])

    split_input_list(infile, num_shares)
