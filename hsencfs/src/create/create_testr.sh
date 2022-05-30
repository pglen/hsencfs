#!/bin/bash

. vars.sh

fusermount -u ~/secrets >/dev/null 2>&1
../tools/bpenc2 -f -p $PASS test/testfile ~/.secrets/testfile2
../tools/bpdec2 -f  -p $PASS  ~/.secrets/testfile2 test/testfile3
diff -s test/testfile test/testfile3








