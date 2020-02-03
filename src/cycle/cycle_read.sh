#!/bin/bash

. ./vars.sh

TESTFILE=aa5000.txt
TESTFILE2=aaa5000.txt
TESTFILE3=aaaa5000.txt

fusermount -u $DROOT

./hsencfs -q -l 4 -p $PASS $DROOT
dd  if=~/secrets/$TESTFILE2 of=test/$TESTFILE3 bs=13
diff -s test/$TESTFILE test/$TESTFILE3






