#!/bin/bash

cd $( dirname $0)

TESTDIR=~/test_secrets

MMM=$(mount | grep $TESTDIR)
if [ "$MMM" == "" ] ; then
    echo Not mounted: \'$TESTDIR\'
    exit 1
fi

rm -rf $TESTDIR/*

mkdir  $TESTDIR/dir1
echo "aa" > $TESTDIR/dir1/aa
chmod uog-rwx $TESTDIR/dir1
ls -ld $TESTDIR/dir1

chmod  u-wrx $TESTDIR/dir1

#echo "bb" > $TESTDIR/dir1/bb

#ls -lR $TESTDIR
chmod  u+wrx $TESTDIR/dir1
ls -ld $TESTDIR/dir1

#chmod  a+wrx $TESTDIR/dir1
#rm -r $TESTDIR/dir1
#ls -lR $TESTDIR

# EOF

