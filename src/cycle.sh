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
    echo "Waning: cannot unmount; err=$ERR"
    #echo
fi

echo

./hsencfs -q -l 9 -p 1234 ~/secrets ~/.secrets

ERR=$?
if [ "$ERR" != "0" ] ; then
    echo $ERR "Cannot mount. err=" $ERR
    exit
fi

rm -rf ~/secrets/*
rm -rf ~/secrets/.deps/*

echo Compilation Done, Begin tests ...
echo -------------------------------------------------------
echo "Tests:  (silent if all is OK)"

echo Direct "(for read / write test)"

function test_direct {
    #rm -f ~/.secrets/$1
    cp test_data/$1 ~/secrets/$1
    diff -q test_data/$1 ~/secrets/$1  # note the missing dot
}

test_direct aa300.txt
test_direct aa4096.txt
test_direct aa4500.txt
test_direct aa9000.txt
test_direct aa12288.txt

echo Copy "(for boundary aligned copy test)"

shopt -s dotglob
rm -rf ~/secrets/*

cp -r ../hello/* ~/secrets
diff -qr ../hello ~/secrets/
ERR=$?
if [ "$ERR" != "0" ] ; then
    echo "Error: Cannot pass copy stage; err=$ERR"
    exit
fi

# Test for match between the two subsystems:

echo test rzig

function test_rzig {
    cp test_data/$1 ~/secrets/$1
    ./tests/zigzag  ~/secrets/$1  test_data/$1.rev
    diff -q test_data/$1 test_data/$1.rev
    rm -f test_data/$1.rev
}

test_rzig aa300.txt
test_rzig aa4096.txt
test_rzig aa4500.txt
test_rzig aa9100.txt

echo test onejump

rm -f jump.txt
./tests/onejump jump.txt
rm -f ~/secrets/jump.txt
./tests/onejump ~/secrets/jump.txt
diff jump.txt ~/secrets/jump.txt
#rm -f jump.txt

ERR=$?
if [ "$ERR" != "0" ] ; then
    echo "Error: Cannot pass onejump stage; err=$ERR"
    exit
fi

echo test farwrite

rm -f farwrite.txt
./tests/farwrite farwrite.txt
./tests/farwrite ~/secrets/farwrite.txt
diff -q farwrite.txt ~/secrets/farwrite.txt
ERR=$?
if [ "$ERR" != "0" ] ; then
    echo "Error: Cannot pass farwrite stage; err=$ERR"
    exit
fi

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

echo test zigzag

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

echo test Zigjump

# Test if utility is OK
#test_item ./tests/zigjump test_data tmp aa5000.txt

# The problem Items
test_item ./tests/zigjump test_data ~/secrets aa3000.txt
test_item ./tests/zigjump test_data ~/secrets aa4096.txt
test_item ./tests/zigjump test_data ~/secrets aa5000.txt  # this one
test_item ./tests/zigjump test_data ~/secrets aa5500.txt
test_item ./tests/zigjump test_data ~/secrets aa9100.txt
test_item ./tests/zigjump test_data ~/secrets aa12288.txt

#echo Done

# EOF
