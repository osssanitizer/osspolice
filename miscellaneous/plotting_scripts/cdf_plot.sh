#!/usr/bin/gnuplot
#set format '$%g$'
set terminal png

#set terminal epslatex color colortext size 8cm, 6cm  font "" 8 header \
#   "\\newcommand{\\ft}[0]{\\footnotesize}"
#set output 'cdf.tex'
set output 'cdf.png'
set datafile sep','

#set size square 0.75,0.75
#set title 'Strings in Repos'
#set title 'Strings in APKs'
set title 'Features in APKs'
set xlabel '# Features'
#set xlabel '# Repos'
set ylabel 'CDF (APKs)'
#set ylabel 'CDF (Repos)'

set yrange [0:1]
set logscale x

unset colorbox

set key bottom right
#set key width 5
#set key font ",1"

#set label at 30,200

#default|podo|classic
#set colorsequence default

set style line 1 lt 1 lc rgb "red"  lw 2 pt 1 ps 1 pi 0
set style line 2 lt 1 lc rgb "blue"  lw 2 pt 2 ps 1 pi 0
set style line 3 lt 1 lc rgb "magenta"  lw 2 pt 3 ps 1 pi 0
set style line 4 lt 1 lc rgb "brown"  lw 2 pt 4 ps 1 pi 0
set style line 5 lt 9 lc rgb "brown"  lw 2 pt 5 ps 1 pi 0
set style line 6 lt 9 lc rgb "cyan"  lw 2 pt 6 ps 1 pi 0
set style line 7 lt 17 lc rgb "black"  lw 2 pt 7 ps 1 pi 0
set style line 8 lt 17 lc rgb "orange"  lw 2 pt 8 ps 1 pi 0
set style line 9 lt 1 lc rgb "grey"  lw 2 pt 1 ps 1 pi 0
set style line 10 lt 1 lc rgb "orangered"  lw 2 pt 2 ps 1 pi 0
set style line 11 lt 1 lc rgb "bluered"  lw 2 pt 3 ps 1 pi 0
set style line 12 lt 1 lc rgb "blackblue"  lw 2 pt 4 ps 1 pi 0
set style line 13 lt 9 lc rgb "gold"  lw 2 pt 5 ps 1 pi 0
set style line 14 lt 9 lc rgb "violet"  lw 2 pt 6 ps 1 pi 0

xl(c) = sprintf('%s', strcol(c))

plot "/tmp/cout" using 1:2 with linespoints ls 1 title '# Functions',\
	"" using 3:4 with linespoints ls 2 title '# Strings (ASCII, >= 3 bytes)',\
#plot "/tmp/cout" using 1:2 with linespoints ls 1 title '# Strings (>= 3 bytes)',\
#plot "/tmp/cout" using 1:2 with linespoints ls 1 title 'Total (>= 2 bytes)',\
#	"" using 3:4 with linespoints ls 2 title 'ASCII (>= 2 bytes)',\
#	"" using 5:6 with linespoints ls 3 title 'Total (>= 4 bytes)',\
#	"" using 7:8 with linespoints ls 4 title 'ASCII (>= 4 bytes)',\
#	"" using 9:10 with linespoints ls 5 title 'Total (>= 6 bytes)',\
#	"" using 11:12 with linespoints ls 6 title 'ASCII (>= 6 bytes)',\
#	"" using 13:14 with linespoints ls 7 title 'Total (>= 8 bytes)',\
#	"" using 15:16 with linespoints ls 8 title 'ASCII (>= 8 bytes)',\
#	"" using 17:18 with linespoints ls 9 title 'Total (>= 10 bytes)',\
#	"" using 19:20 with linespoints ls 10 title 'ASCII (>= 10 bytes)',\
#	"" using 21:22 with linespoints ls 11 title 'Total (>= 12 bytes)',\
#	"" using 23:24 with linespoints ls 12 title 'ASCII (>= 12 bytes)',\
#	"" using 25:26 with linespoints ls 13 title 'Total (>= 14 bytes)',\
#	"" using 27:28 with linespoints ls 14 title 'ASCII (>= 14 bytes)'
