#!/bin/bash

fusermount -u ~/secret >/dev/null 2>&1
rm test/aaaa4096.txt

make

./hsencfs -q -l 4 -p 1234 ~/secret
cp ~/secret/aaa4096.txt test/aaaa4096.txt
diff -s test/aa4096.txt test/aaaa4096.txt
fusermount -u ~/secret  >/dev/null 2>&1








