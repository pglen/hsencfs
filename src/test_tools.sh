#!/bin/bash

pushd `pwd`
cd ..
make
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

# ------------------------------------------------------------------------
# test the tools themselves
# ------------------------------------------------------------------------
echo "Test tools:  (silent if all is OK)"

function test_tool {
    echo $1 "->" $2
    $1 $2 $3
    diff -q $2 $3
}

test_tool ./tests/zigjump  test_data/aa3000.txt ddd
test_tool ./tests/zigjump  test_data/aa5000.txt ddd
test_tool ./tests/zigjump  test_data/aa9000.txt ddd
rm ddd

test_tool ./tests/zigzag  test_data/aa3000.txt eee
test_tool ./tests/zigzag  test_data/aa5000.txt eee
test_tool ./tests/zigzag  test_data/aa9000.txt eee
rm eee

test_tool ./tests/seekcp  test_data/aa3000.txt fff
test_tool ./tests/seekcp  test_data/aa5000.txt fff
test_tool ./tests/seekcp  test_data/aa9000.txt fff
rm fff

test_tool ./tests/dualwrite  test_data/aa3000.txt ggg
test_tool ./tests/dualwrite  test_data/aa5000.txt ggg
test_tool ./tests/dualwrite  test_data/aa9000.txt ggg
rm ggg

# EOF
