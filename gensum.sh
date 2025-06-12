#!/bin/bash

# Create a new sum for the project
# Copyright by Peter Glen. See open source license for details.

#PROG=shasum
#OUTFILE=sha1

# Thu 12.Jun.2025  runs faster by using md5 (which is sufficient here)
PROG=md5sum
OUTFILE=md5

echo -n "Checksum project with $PROG  ... "
cp $OUTFILE.sum $OUTFILE.sum.old >/dev/null 2>&1
touch "SUMFILE"
#find . -maxdepth 1 -type f -exec shasum {} >$TMPFILE \;
find .  -type f -exec $PROG {} >$OUTFILE.sum.tmp \;
echo OK

echo -n "Cleaning tmp files ... "
# Remove SUMFILE and OUTFILES* files from the check
cat $OUTFILE.sum.tmp | grep -E -v \
      "(SUMFILE)|($OUTFILE.sum.tmp)|($OUTFILE.sum)" > $OUTFILE.sum
rm $OUTFILE.sum.tmp
echo OK

# The sumfile should also be checked against auxiliarry sources
echo -n "Generating SUMFILE ... "
$PROG $OUTFILE.sum > SUMFILE
echo OK
#echo Done Checksum.
