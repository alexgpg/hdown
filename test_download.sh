#!/bin/sh

URL=http://lunduke.com/justme.png

./hdown $URL
rm -f wget_justme.png
wget $URL -O wget_justme.png
./cmp_files.sh justme.png wget_justme.png
