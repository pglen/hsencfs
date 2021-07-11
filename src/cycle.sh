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
#rm -f ddd
#./tests/zigjump test_data/aa9000.txt ddd
#diff  test_data/aa9000.txt ddd

#../tools/bpdec2 -p 1234 -f  ~/.secrets/aa4096.txt aaaa
#diff -r aaaa test_data/aa4096.txt

#../tools/bpdec2 -p 1234 -f  ~/.secrets/aa4500.txt aaaa
#diff -r aaaa test_data/aa4500.txt

#../tools/bpdec2 -p 1234 -f  ~/.secrets/aa300.txt aaaa
#diff -r aaaa test_data/aa300.txt

echo Compilation Done, test
echo -------------------------------------------------------
echo "Tests:  (silent if all is OK)"
diff -qr ~/secrets/ ../hello

# test for match between the two subsystems:

../tools/bpenc2 -p 1234 test_data/aa4096.txt ~/.secrets/aa4096.txt
diff -q test_data/aa4096.txt ~/secrets/aa4096.txt  # note the missing dot

../tools/bpenc2 -p 1234 test_data/aa4500.txt ~/.secrets/aa4500.txt
diff -q test_data/aa4500.txt ~/secrets/aa4500.txt  # note the missing dot

../tools/bpenc2 -p 1234 test_data/aa300.txt ~/.secrets/aa300.txt
diff -q test_data/aa300.txt ~/secrets/aa300.txt  # note the missing dot

rm -f bbb
./tests/onejump bbb
./tests/onejump ~/secrets/bbb
diff bbb ~/secrets/bbb

rm -f farwrite.txt
./tests/farwrite farwrite.txt
./tests/farwrite ~/secrets/farwrite.txt
diff -q farwrite.txt ~/secrets/farwrite.txt

../tools/bpenc2 -p 1234 test_data/aa9000.txt ~/.secrets/aa9000.txt
diff -q test_data/aa9000.txt ~/secrets/aa9000.txt

function test_one {
    IN=$2/$4;  OUT=$3/$4
    rm -f $OUT
    echo $1 "--" $IN  $OUT
    $1 $IN  $OUT
    diff -q $IN  $OUT
}

test_one ./tests/zigzag test_data ~/secrets aa3000.txt
test_one ./tests/zigzag test_data ~/secrets aa4096.txt
test_one ./tests/zigzag test_data ~/secrets aa5000.txt
test_one ./tests/zigzag test_data ~/secrets aa5500.txt

test_one ./tests/zigjump test_data ~/secrets aa3000.txt
test_one ./tests/zigjump test_data ~/secrets aa5000.txt
#test_one ./tests/zigjump test_data ~/secrets aa5500.txt
#test_one ./tests/zigjump test_data ~/secrets aa9000.txt
#test_one ./tests/zigjump test_data ~/secrets aa9100.txt

#echo Done

# eof