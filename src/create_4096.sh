#!/bin/bash

fusermount -u ~/secret >/dev/null 2>&1

dd if=/dev/zero bs=4096 count=1 | tr '\0' 'a' > test/aa4096.txt
../tools/bpenc2 -f -p 1234 test/aa4096.txt ~/.secret/aaa4096.txt


