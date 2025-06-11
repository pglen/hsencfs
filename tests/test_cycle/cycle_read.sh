#!/bin/bash

. ./vars.sh

# Error descriptions (to aid testing)
# if aa300 is bad .. side buffer issue
# if aa4096 is bad .. block alignment issue
# if aa5000 is bad .. final block + sidebuffer issue

aa=`mount | grep secrets`
if [ "$aa" == "" ] ; then
    echo mount secrets first
    exit 0
fi

# Bash function ot assemble names

read_file()
{
    dd  if=~/secrets/a$1 of=test/aa$1 ibs=$2 obs=$2 2>/dev/null

    echo -n "bs=$2 "
    #diff -qs test/$1 test/aa$1; ERR=$?
    pgdiff -qs test/$1 test/aa$1; ERR=$?

    if [ "$ERR" != "0" ] ; then
         #echo -e $RED"bs=$2 Error: $ERR " $NC
         #ls -l test/$1 test/aa$1
         echo -n ""
    else
         #echo -en "$GREEN OK $NC"
         echo -n ""
    fi
}

# Create test cases for read:

read_file "aa4096.txt" 4096
read_file "aa8192.txt" 4096
read_file "aa300.txt" 4096
read_file "aa5000.txt" 4096
read_file "aa9000.txt" 4096

read_file "aa4096.txt" 40
read_file "aa8192.txt" 41
read_file "aa300.txt"  23
read_file "aa5000.txt" 80
read_file "aa9000.txt" 12

read_file "aa4096.txt" 409
read_file "aa8192.txt" 412
read_file "aa300.txt"  23
read_file "aa5000.txt" 8000
read_file "aa9000.txt" 406









