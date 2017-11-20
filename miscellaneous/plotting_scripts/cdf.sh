#!/bin/bash
input=$1
start=$2
end=$3
total=$(wc -l $1)
output=$(basename $1)
for i in $(seq $start $end)
	do
		cat $input | cut -f$i -d, | sort -n | uniq -c | awk "{m=\$1+m; printf \"%06d, %.2f\n\", \$2, m/${total}}" > /tmp/$output.$i.csv
	done

paste -d, $(seq -f "/tmp/$output.%g.csv" $start $end) > /tmp/cout

