#!/bin/bash

fusermount -u ~/secret >/dev/null 2>&1

dd if=/dev/zero bs=8192 count=1 | tr '\0' 'a' > test/aa8192.txt
../tools/bpenc2 -f -p 1234 test/aa8192.txt ~/.secrets/aaa8192.txt
../tools/bpdec2 -f -p 1234 ~/.secrets/aaa8192.txt test/aaaa8192.txt
echo -n "Compare Results: "
diff -s test/aa8192.txt test/aaaa8192.txt




