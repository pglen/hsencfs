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
    echo -n "bs=$2 "
    diff -qs test/$1 ~/secrets/a$1; ERR=$?

    if [ "$ERR" != "0" ] ; then
         echo -e "$RED  ***** bs=$2 Error: $ERR "
         diff  -qs test/$1 ~/secrets/a$1;
         ls -l test/$1 ~/secrets/a$1
         echo -e $NC
    fi
}

write_file "aa4096.txt" 4096
#write_file "aa8192.txt" 4096
#write_file "aa300.txt" 4096
#write_file "aa5000.txt" 4096
#write_file "aa9000.txt" 4096
#
#write_file "aa4096.txt"  2000
#write_file "aa8192.txt" 4000
#write_file "aa300.txt"  200
#write_file "aa5000.txt" 800
#write_file "aa9000.txt" 300
#
#write_file "aa4096.txt" 345
#write_file "aa8192.txt" 255
#write_file "aa300.txt"  230
#write_file "aa5000.txt" 800
#write_file "aa9000.txt" 406
#

