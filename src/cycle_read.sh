#!/bin/bash

fusermount -u ~/secret >/dev/null 2>&1
make
./hsencfs -q -l 4 -p 1234 ~/.secret ~/secret
cp ~/secret/testfile2 test/testfile4
diff -s test/testfile test/testfile4
fusermount -u ~/secret





