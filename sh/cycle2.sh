#!/bin/bash

MYDIR=$(dirname $0)
TESTDIR=~/test_secrets
TESTDATA=~/.test_secrets
PROMPT="Ended test, press Enter key to continue ... "

umount $TESTDIR   >/dev/null 2>&1
rm -rf $TESTDIR   >/dev/null 2>&1
rm -rf $TESTDATA  >/dev/null 2>&1
mkdir -p $TESTDIR >/dev/null 2>&1

make
ERR=$?
if [ "$ERR" != "0" ] ; then
    echo "Cannot compile. $TESTDIR err=$ERR"
    read -p "Press a key ... "
    exit
fi

$MYDIR/src/hsencfs -o -l 5 $TESTDIR
ERR=$?
if [ "$ERR" != "0" ] ; then
    echo "Cannot mount. $TESTDIR err=$ERR"
    read -p "Press a key ... "
    exit
fi

echo "Hello World" > $TESTDIR/aa
ls -l $TESTDIR/aa $TESTDATA/aa
cat $TESTDIR/aa

echo -n "$PROMPT "
read

# EOF
