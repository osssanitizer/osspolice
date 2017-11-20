#!/usr/bin/gnuplot
#set format '$%g$'
set terminal png

#set terminal epslatex color colortext size 8cm, 6cm  font "" 8 header \
#   "\\newcommand{\\ft}[0]{\\footnotesize}"
#set output 'cdf.tex'
set output 'hist.png'
set datafile sep','

set auto x
set yrange [0:300000]
set style data histogram
set style histogram cluster gap 1
set style fill solid border -1
set boxwidth 0.9
set xtic rotate by -45 scale 0
#set bmargin 10 
plot '../hist.csv' using 1:xtic(2)
