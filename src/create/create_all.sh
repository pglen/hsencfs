#!/bin/bash

fusermount -u ~/secret >/dev/null 2>&1

create_file()

{
    dd if=/dev/zero bs=$1 count=1 2>xx | tr '\0' 'a' > test/aa$1.txt
    ../tools/bpenc2 -f -p 1234 test/aa$1.txt ~/.secrets/aaa$1.txt
    ../tools/bpdec2 -f -p 1234 ~/.secrets/aaa$1.txt test/aaaa$1.txt
    echo -n "Comp Res: $1 "
    diff -s -a test/aa$1.txt test/aaaa$1.txt
}

rm test/*

create_file 300
create_file 4096
create_file 5000
create_file 8192
create_file 9000






