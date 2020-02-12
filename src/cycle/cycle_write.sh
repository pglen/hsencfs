#!/bin/bash

. ./vars.sh

aa=`mount | grep secrets`

if [ "$aa" == "" ] ; then
    echo mount secrets first
    exit 0
fi

# Bash function to assemble names

write_file()

{
    dd  of=~/secrets/a$1 if=test/$1 bs=$2 2>/dev/null
    #echo -n "bs=$2 "
    diff -qs test/$1 ~/secrets/a$1; ERR=$?

    #ls -l test/$1 ~/secrets/a$1
    if [ "$ERR" != "0" ] ; then
         echo -e "$RED  ***** Error: $ERR $NC"
    fi
}

write_file "aa4096.txt" 4096
write_file "aa8192.txt" 4096
write_file "aa300.txt" 4096
write_file "aa5000.txt" 4096
write_file "aa9000.txt" 4096

write_file "aa4096.txt"  2000
write_file "aa8192.txt" 41
write_file "aa300.txt"  200
write_file "aa5000.txt" 80
write_file "aa9000.txt" 12

write_file "aa4096.txt" 409
write_file "aa8192.txt" 412
write_file "aa300.txt"  23
write_file "aa5000.txt" 8000
write_file "aa9000.txt" 406










