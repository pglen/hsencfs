#!/bin/bash

pushd `pwd`
cd ..
make -s
ERR=$?
popd

if [ "$ERR" != "0" ] ; then
    echo "Cannot compile err=$ERR"
    exit
fi

fusermount -u ~/secrets
ERR=$?
if [ "$ERR" != "0" ] ; then
    echo "Warning: cannot unmount; err=$ERR"
    #echo
    #exit
fi

echo -n Starting hsencfs ...

./hsencfs -q -l 0 -p 1234 ~/secrets ~/.secrets
ERR=$?
echo
if [ "$ERR" != "0" ] ; then
    echo $ERR "Cannot mount. err=" $ERR
    exit
fi

echo Compilation and start Done, Begin tests ...

rm -rf ~/secrets/*

echo -------------------------------------------------------
echo "Tests:  (silent if all is OK)"

echo Direct "(for read / write test)"

function test_direct {
    #rm -f ~/.secrets/$1
    cp test_data/$1 ~/secrets/$1
    diff -q test_data/$1 ~/secrets/$1  # note the missing dot
    ERR=$?

    if [ "$ERR" != "0" ] ; then
        echo "Error: Cannot pass direct stage; err=$ERR"
        exit
    fi
}

test_direct aa300.txt
test_direct aa4096.txt
test_direct aa4500.txt
test_direct aa9000.txt
test_direct aa12288.txt

# Test for match between the two subsystems:

echo Test onejump

rm -f jump.txt ~/secrets/jump.txt
./tests/onejump jump.txt
./tests/onejump ~/secrets/jump.txt
diff jump.txt ~/secrets/jump.txt
rm -f jump.txt ~/secrets/jump.txt

ERR=$?
if [ "$ERR" != "0" ] ; then
    echo "Error: Cannot pass onejump stage; err=$ERR"
    exit
fi

echo Test rzig

#rm -rf ~/secrets/*

function test_rzig {
    cp test_data/$1 ~/secrets/$1
    ./tests/zigzag  ~/secrets/$1  test_data/$1.rev
    diff -q test_data/$1 test_data/$1.rev
    ERR=$?
    rm -f test_data/$1.rev

    if [ "$ERR" != "0" ] ; then
        echo "Error: Cannot pass zigzag stage; err=$ERR"
        exit
    fi
}

test_rzig aa300.txt
test_rzig aa4096.txt
test_rzig aa4500.txt
test_rzig aa9100.txt

echo Test farwrite

function far_write
{
    rm -f $1
    ./tests/farwrite $1
    ./tests/farwrite ~/secrets/$1
    diff -q $1 ~/secrets/$1
    ERR=$?
    if [ "$ERR" != "0" ] ; then
        echo "Error: Cannot pass farwrite stage; err=$ERR"
        exit
    fi
}

far_write  farwrite.txt
rm  -f farwrite.txt ~/secrets/farwrite.txt

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
}

echo Test zigzag

# Test if utility is OK
#test_item ./tests/zigzag test_data tmp aa300.txt

test_item ./tests/zigzag test_data ~/secrets aa300.txt
test_item ./tests/zigzag test_data ~/secrets aa4096.txt
test_item ./tests/zigzag test_data ~/secrets aa5000.txt
test_item ./tests/zigzag test_data ~/secrets aa8192.txt
test_item ./tests/zigzag test_data ~/secrets aa9000.txt
test_item ./tests/zigzag test_data ~/secrets aa12288.txt
#exit
#test_item ./tests/zigzag test_data ~/secrets aa16384.txt

echo Test Zigjump

# Test if utility is OK
#test_item ./tests/zigjump test_data tmp aa5000.txt

# The problem Items
#  Sun 08.May.2022 succeeded with virtual

test_item ./tests/zigjump test_data ~/secrets aa3000.txt
test_item ./tests/zigjump test_data ~/secrets aa4096.txt
test_item ./tests/zigjump test_data ~/secrets aa5000.txt  # this one
test_item ./tests/zigjump test_data ~/secrets aa5500.txt
test_item ./tests/zigjump test_data ~/secrets aa9100.txt
test_item ./tests/zigjump test_data ~/secrets aa12288.txt

# Jumpread

echo Test Jumpread

function jump_read
{
    rm -f $1
    ./tests/jumpread $1
    ./tests/jumpread ~/secrets/$1
    diff -q $1 ~/secrets/$1
    ERR=$?
    if [ "$ERR" != "0" ] ; then
        echo "Error: Cannot pass jumpread stage; err=$ERR"
        exit
    fi
}

jump_read  jumpread.txt
rm jumpread.txt ~/secrets/jumpread.txt

if [ "$1" == "pause" ] ; then
    read aa
fi

echo Copy "(for boundary aligned copy test)"

shopt -s dotglob
rm -rf ~/.secrets/*
rm -rf ~/secrets/*

cp -r ../hello/* ~/secrets
diff -qr ../hello ~/secrets/
shopt -u dotglob

ERR=$?
if [ "$ERR" != "0" ] ; then
    echo "Error: Cannot pass copy stage; err=$ERR"
    exit
fi


#echo Done

# EOF
