#!/bin/bash

. ./vars.sh

aa=`mount | grep secrets`
if [ "$aa" == "" ] ; then
    echo mount secrets first
    exit 0
fi

#dd if=test/aa5000.txt of=~/secrets/$TESTFILE5 bs=2048
#diff -s ~/secrets/$TESTFILE5 test/aa5000.txt

dd if=test/aa4096.txt of=~/secrets/aaa4096.txt bs=202
diff -s ~/secrets/aaa4096.txt test/aa4096.txt








