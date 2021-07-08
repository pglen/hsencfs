#!/bin/bash

# use: genfile file_size fill_letter
function genfile() {
    dd if=/dev/zero bs=1 count=$1 2>/dev/null | tr \\0 a > $2$2$1.txt
}

# These values are picked to excersize the data flow wth pre boundary
# and post boundary test cases

genfile 300     a
genfile 3000    a
genfile 4096    a
genfile 4500    a
genfile 5000    a
genfile 8192    a
genfile 9000    a

# EOF
