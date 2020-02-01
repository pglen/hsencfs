#!/bin/bash

#
#make
#fusermount -u ~/secret
./hsencfs -q -l 4 -p 1234 ~/.secret ~/secret
cp test/testfile ~/secret/testfile.enc
cp ~/secret/testfile.enc test/testfile.dec
diff test/testfile test/testfile.dec
fusermount -u ~/secret





