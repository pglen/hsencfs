#!/bin/bash

. ./vars.sh

TESTFILE=aa5000.txt
TESTFILE2=aaa5000.txt
TESTFILE5=aaaaaa5000.txt

if [ ! -f ~/secrets/$TESTFILE2 ] ; then
    echo mount secrets first
    exit 0
fi

#dd if=test/aa5000.txt of=~/secrets/$TESTFILE5 bs=2048
#diff -s ~/secrets/$TESTFILE5 test/aa5000.txt

dd if=test/aa4096.txt of=~/secrets/aaa4096.txt bs=13
diff -s ~/secrets/aaa4096.txt test/aa4096.txt







