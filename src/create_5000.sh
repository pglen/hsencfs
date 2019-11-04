#!/bin/bash

fusermount -u ~/secret >/dev/null 2>&1

dd if=/dev/zero bs=5000 count=1 | tr '\0' 'a' > test/aa5000.txt
../tools/bpenc2 -f -p 1234 test/aa5000.txt ~/.secret/aaa5000.txt
../tools/bpdec2 -f -p 1234 ~/.secret/aaa5000.txt test/aaaa5000.txt
diff -s test/aa5000.txt test/aaaa5000.txt




