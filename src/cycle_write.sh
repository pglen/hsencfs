#!/bin/bash

fusermount -u ~/secret >/dev/null 2>&1
make
./hsencfs -q -l 4 -p 1234 ~/.secret ~/secret
cp test/aa5000.txt ~/secret/aaa5000.txt
diff -s ~/secret/aaa5000.txt test/aa5000.txt
fusermount -u ~/secret






