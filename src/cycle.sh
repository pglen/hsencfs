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
cp -r ../hello/* ~/secrets

echo Compilation Done, Begin tests ...
echo -------------------------------------------------------
echo "Tests:  (silent if all is OK)"
diff -qr ~/secrets/ ../hello

# test for match between the two subsystems:

function test_direct {
    ../tools/bpenc2 -p 1234 test_data/$1 ~/.secrets/$1
    diff -q test_data/$1 ~/secrets/$1  # note the missing dot
}

function test_rzig {
    ../tools/bpenc2 -p 1234 -f test_data/$1 ~/.secrets/$1
    ./tests/zigzag  ~/secrets/$1  test_data/$1.rev
    diff -q test_data/$1 test_data/$1.rev
}

test_direct aa300.txt
test_direct aa4096.txt
test_direct aa4500.txt
test_direct aa9000.txt

echo Rzig

test_rzig aa300.txt
test_rzig aa4096.txt
test_rzig aa4500.txt
test_rzig aa9000.txt

rm -f bbb
./tests/onejump bbb
./tests/onejump ~/secrets/bbb
diff bbb ~/secrets/bbb
rm -d bbb

rm -f farwrite.txt
./tests/farwrite farwrite.txt
./tests/farwrite ~/secrets/farwrite.txt
diff -q farwrite.txt ~/secrets/farwrite.txt

function test_item {
    IN=$2/$4;  OUT=$3/$4
    rm -f $OUT
    #echo $1 "--" $IN  $OUT
    $1 $IN  $OUT
    diff -q $IN  $OUT
}

test_item ./tests/zigzag test_data ~/secrets aa300.txt
test_item ./tests/zigzag test_data ~/secrets aa4096.txt
test_item ./tests/zigzag test_data ~/secrets aa5000.txt
test_item ./tests/zigzag test_data ~/secrets aa8192.txt
test_item ./tests/zigzag test_data ~/secrets aa9000.txt

# The problem Items
test_item ./tests/zigjump test_data ~/secrets aa3000.txt
test_item ./tests/zigjump test_data ~/secrets aa5500.txt
test_item ./tests/zigjump test_data ~/secrets aa9100.txt

#echo Done

# EOF