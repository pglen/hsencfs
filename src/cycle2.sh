#!/bin/bash

TESTDIR=~/test_secrets
TESTDATA=~/.test_secrets

PROMPT="Press Enter key to continue ... "

#echo $(pwd)
#pushd `pwd`
#cd ..
#make -s
#ERR=$?
#popd
#if [ "$ERR" != "0" ] ; then
#    echo "Cannot compile err=$ERR"
#    exit
#fi

umount $TESTDIR
rm -rf $TESTDIR
rm -rf $TESTDATA

mkdir -p $TESTDIR

#fusermount -u $TESTDIR
#ERR=$?
#if [ "$ERR" != "0" ] ; then
#    #echo "Warning: cannot unmount; err=$ERR"
#    exit
#fi
#echo -n Starting hsencfs ...

./hsencfs -o -a ../hsaskpass.py -l 5 -p 1234 $TESTDIR
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

echo
read -p "Press a key ... "

# EOF
