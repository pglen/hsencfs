#!/bin/bash

make
ERR=$?
if [ "$ERR" != "0" ] ; then
    echo "Cannot compile err=$ERR"
    exit
fi

fusermount -u ~/secrets
ERR=$?
if [ "$ERR" != "0" ] ; then
    #echo "Waning: cannot unmount; err=$ERR"
    echo
fi

./hsencfs -q -l 9 -p 1234 ~/secrets ~/.secrets

ERR=$?
if [ "$ERR" != "0" ] ; then
    echo $ERR "Cannot mount. err=" $ERR
    exit
fi

rm -rf ~/secrets/*
rm -rf ~/secrets/.deps/*
cp -r ../hello/* ~/secrets

echo "Tests:  (silent if all is OK)"
diff -qr ~/secrets/ ../hello

# test for match between the two subsystems:

../tools/bpenc2 -p 1234 test_data/aa4096.txt ~/.secrets/aa4096.txt
../tools/bpdec2 -p 1234 -f  ~/.secrets/aa4096.txt aaaa
diff -r aaaa test_data/aa4096.txt
diff -q test_data/aa4096.txt ~/secrets/aa4096.txt  # note the missing dot

../tools/bpenc2 -p 1234 test_data/aa4500.txt ~/.secrets/aa4500.txt
../tools/bpdec2 -p 1234 -f  ~/.secrets/aa4500.txt aaaa
diff -r aaaa test_data/aa4500.txt
diff -q test_data/aa4500.txt ~/secrets/aa4500.txt  # note the missing dot

../tools/bpenc2 -p 1234 test_data/aa300.txt ~/.secrets/aa300.txt
../tools/bpdec2 -p 1234 -f  ~/.secrets/aa300.txt aaaa
diff -r aaaa test_data/aa300.txt
diff -q test_data/aa300.txt ~/secrets/aa300.txt  # note the missing dot

rm -f bbb
./tests/onejump bbb
./tests/onejump ~/secrets/bbb
diff bbb ~/secrets/bbb

rm -f aaa
./tests/farwrite aaa
./tests/farwrite ~/secrets/aaa
diff aaa ~/secrets/aaa

./tests/zigzag test_data/aa3000.txt  ~/secrets/aa3000.txt
diff test_data/aa3000.txt ~/secrets/aa3000.txt

./tests/zigzag test_data/aa5000.txt  ~/secrets/aa5000.txt
diff test_data/aa5000.txt ~/secrets/aa5000.txt
echo Done




