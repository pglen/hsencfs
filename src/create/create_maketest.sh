#!/bin/bash

. vars.sh

fusermount -u ~/secrets >/dev/null 2>&1

../tools/bpenc2 -f -p $PASS Makefile ~/.secrets/Makefile.enc
../tools/bpdec2 -f  -p $PASS  ~/.secrets/Makefile.enc test/Makefile.dec
diff -s Makefile test/Makefile.dec


