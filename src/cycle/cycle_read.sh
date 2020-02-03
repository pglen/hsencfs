#!/bin/bash

. ./vars.sh

TESTFILE=aa5000.txt
TESTFILE2=aaa5000.txt
TESTFILE3=aaaa5000.txt

if [ ! -f ~/secrets/$TESTFILE2 ] ; then
    echo mount secrets first
    exit 0
fi

dd  if=~/secrets/$TESTFILE2 of=test/$TESTFILE3 ibs=13
diff -s test/$TESTFILE test/$TESTFILE3






