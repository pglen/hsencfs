#!/bin/bash

# Copy data to folder, compare

mm=`mount` 
mmm=`echo $mm | grep testsecrets`
if [ "$mmm" == "" ] ; then
    echo This utility was meant to be executed from the Makefile.
    exit 1
fi
  
# Copy and compare, print diagnosis
  
cp -a Makefile ~/testsecrets
diff  Makefile ~/testsecrets/Makefile
ERR=$?
if [ $ERR == 0 ] ; then
    echo Encryption test passed.
else
    echo
    echo Encryption test FAILED!
    echo
    exit 1
fi    

exit 0




