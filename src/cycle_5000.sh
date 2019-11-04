#!/bin/bash

fusermount -u ~/secret >/dev/null 2>&1
make
./hsencfs -q -l 4 -p 1234 ~/.secret ~/secret || exit
cp ~/secret/aaa5000.txt test/aaaa5000.txt
diff -s test/aa5000.txt test/aaaa5000.txt
fusermount -u ~/secret








