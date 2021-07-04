#!/bin/bash

make
ERR=$?
if [ "$ERR" != "0" ] ; then
    echo $ERR "Cannot compile"
    exit
fi

fusermount -u ~/secrets
ERR=$?
if [ "$ERR" != "0" ] ; then
    echo "Waning: cannot unmount; err=" $ERR
fi

./hsencfs -q -l 9 -p 1234 ~/secrets ~/.secrets

ERR=$?
if [ "$ERR" != "0" ] ; then
    echo $ERR "Cannot mount. err=" $ERR
    exit
fi

rm -rf ~/secrets/*
cp -a ~/pgsrc/hello/* ~/secrets
diff -r ~/secrets/ ~/pgsrc/hello
./tests/farwrite aaa
./tests/farwrite ~/secrets/aaa
diff aaa ~/secrets/aaa
rm aaa





