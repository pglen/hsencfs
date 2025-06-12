#!/bin/bash

#PROG=shasum
#OUTFILE=sha1

# Thu 12.Jun.2025  runs faster by using md5 (which is sufficient here)
PROG=md5sum
OUTFILE=md5

# Verify the integrity of our project
#echo -n "Verify project ... "

echo -n "Checking checksum file ... "
$PROG --check --quiet "SUMFILE"
echo Done

echo -n "Checking checksums ... "
$PROG --check --quiet $OUTFILE.sum
echo Done
