#!/bin/bash

# use: genfile file_size fill_letter
function genfile() {
    dd if=/dev/zero bs=1 count=$1 2>/dev/null | tr \\0 a > $2$1.txt
}

# These values are picked to excersize the data flow wth pre boundary
# and post boundary test cases

genfile 300     aa
genfile 3000    aa
genfile 4096    aa
genfile 8100    aa
genfile 4500    aa
genfile 5000    aa
genfile 5500    aa
genfile 8192    aa
genfile 9000    aa
genfile 9100    aa
genfile 12288   aa
genfile 16384   aa
genfile 16500   aa


# EOF
