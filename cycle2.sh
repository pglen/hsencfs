#!/bin/bash

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

./src/hsencfs -o -a ./askpass/hsaskpass.py -l 5 -p 1234 $TESTDIR
ERR=$?
if [ "$ERR" != "0" ] ; then
    echo "Cannot mount. $TESTDIR err=$ERR"
    read -p "Press a key ... "
    exit
fi

#echo Compilation and start Done, Begin tests ...

echo "aa" > $TESTDIR/aa
ls -l $TESTDIR
cat $TESTDIR/aa

#echo
echo -n "$PROMPT "
read
#-p $PROMPT
#"Press a key"

# EOF
