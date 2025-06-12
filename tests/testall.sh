#!/bin/bash

cd $( dirname $0)

TESTDIR=~/test_secrets

MMM=$(mount | grep $TESTDIR)
if [ "$MMM" == "" ] ; then
    echo Not mounted: \'$TESTDIR\'
    exit 1
fi

rm -rf $TESTDIR/*

echo -------------------------------------------------------
echo "Tests: at $TESTDIR  (silent if all is OK) "

echo -n "Direct (read / write test) "

function test_direct {
    #rm -f ~/.secrets/$1
    cp test_data/$1 $TESTDIR/$1
    diff -q test_data/$1 $TESTDIR/$1  # note the missing dot
    ERR=$?

    if [ "$ERR" != "0" ] ; then
        echo "Error: Cannot pass direct stage; err=$ERR"
        exit
    fi
    echo -n "."
}

test_direct aa300.txt
test_direct aa4096.txt
test_direct aa4500.txt
test_direct aa9000.txt
test_direct aa12288.txt

echo
echo -n "Test Rzig "

function test_rzig {
    cp test_data/$1 $TESTDIR$1
    ./zigzag  $TESTDIR$1  test_data/$1.rev
    diff -q test_data/$1 test_data/$1.rev
    ERR=$?
    rm -f test_data/$1.rev

    if [ "$ERR" != "0" ] ; then
        echo "Error: Cannot pass zigzag stage; err=$ERR"
        exit
    fi
    echo -n "."
}

test_rzig aa300.txt
test_rzig aa4096.txt
test_rzig aa4500.txt
test_rzig aa9100.txt

# ------------------------------------------------------------------------

function test_item {
    IN=$2/$4;  OUT=$3/$4
    rm -f $OUT
    #echo $1 "--" $IN  $OUT
    $1 $IN $OUT
    diff -q $IN  $OUT
    ERR=$?
    if [ "$ERR" != "0" ] ; then
        echo "Error: Cannot pass  $1; err=$ERR with: $4"
    exit
    fi
    echo -n "."
}

echo
echo -n "Test Zigzag "

# Test if utility is OK
#test_item ./zigzag test_data tmp aa300.txt

test_item ./zigzag test_data $TESTDIR aa300.txt
test_item ./zigzag test_data $TESTDIR aa4096.txt
test_item ./zigzag test_data $TESTDIR aa5000.txt
test_item ./zigzag test_data $TESTDIR aa8192.txt
test_item ./zigzag test_data $TESTDIR aa9000.txt
test_item ./zigzag test_data $TESTDIR aa12288.txt
#exit
#test_item ./zigzag test_data $TESTDIR aa16384.txt

echo
echo -n "Test Zigjump "

# Test if utility is OK
#test_item ./zigjump test_data tmp aa5000.txt

# The problem Items
#  Sun 08.May.2022 succeeded with virtual

test_item ./zigjump test_data $TESTDIR aa3000.txt
test_item ./zigjump test_data $TESTDIR aa4096.txt
test_item ./zigjump test_data $TESTDIR aa5000.txt  # this one
test_item ./zigjump test_data $TESTDIR aa5500.txt
test_item ./zigjump test_data $TESTDIR aa9100.txt
test_item ./zigjump test_data $TESTDIR aa12288.txt

# Jumpread
echo
echo -n "Test Jumpread "

function jump_read
{
    rm -f $1
    ./jumpread $1
    ./jumpread $TESTDIR/$1
    diff -q $1 $TESTDIR/$1
    ERR=$?
    if [ "$ERR" != "0" ] ; then
        echo "Error: Cannot pass jumpread stage; err=$ERR"
        exit
    fi
    echo -n "."
}

jump_read  jumpread.txt
rm jumpread.txt $TESTDIR/jumpread.txt

if [ "$1" == "pause" ] ; then
    read aa
fi
echo

echo -n "Test Farwrite "

function far_write
{
    rm -f $1
    ./farwrite $1
    ./farwrite $TESTDIR$1
    diff -q $1 $TESTDIR$1
    ERR=$?
    if [ "$ERR" != "0" ] ; then
        echo "Error: Cannot pass farwrite stage; err=$ERR"
        exit
    fi
    echo -n "."
}

far_write  farwrite.txt
rm  -f farwrite.txt $TESTDIR/farwrite.txt
echo

# Test for match between the two subsystems:

echo -n "Test Onejump "

rm -f jump.txt $TESTDIRjump.txt
./onejump jump.txt
./onejump $TESTDIRjump.txt
diff jump.txt $TESTDIRjump.txt
rm -f jump.txt $TESTDIRjump.txt
echo -n "."

ERR=$?
if [ "$ERR" != "0" ] ; then
    echo "Error: Cannot pass onejump stage; err=$ERR"
    exit
fi

echo
echo -n "Test Copy "

shopt -s dotglob
rm -rf $TESTDIR/*
echo -n "."
cp -r test_data/* $TESTDIR
echo -n "."
diff -qr test_data/ $TESTDIR
echo -n "."
shopt -u dotglob

ERR=$?
if [ "$ERR" != "0" ] ; then
    echo "Error: Cannot pass copy stage; err=$ERR"
    exit
fi

function bsimple()
{
    echo $1 >aa
    echo $1 >$TESTDIR/aa
    cat  $TESTDIR/aa > bb
    #echo -n "aa: '" ; hd aa
    #echo -n "bb: '" ; hd bb
    #ls -l aa bb
    #stat --printf="%s " aa bb
    echo -n "."
    diff aa bb
    rm aa bb
}

echo
echo -n "Test Truncate (bash)"

bsimple "aaaaaaa"
bsimple "aabbb"
bsimple "cc"
echo

function bappend()
{
    echo -n $1 >>aa
    echo -n $1 >>$TESTDIR/aa
    echo -n "."
    diff aa $TESTDIR/aa
}

echo -n "Test Append (bash) "

echo -n  "" >aa
echo -n "" >$TESTDIR/aa

bappend "aaa"
bappend "bbbb"
bappend "aaa"

echo
echo Done tests.

# EOF

