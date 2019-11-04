#!/bin/bash
aa=`mount | grep secret`
if [ "$aa" == "" ] ; then
    echo "Not mounted."
    exit 0
fi

diff -s aa ~/secret/aa

#cp aa ~/secret/aaa
#cp ~/secret/aaa bb
#diff -s aa bb >/dev/null
#if [ "$?" == "1" ] ; then
#    #echo $?
#    echo "Test1 FAIL. (files not equal)"
#fi

#cp cc ~/secret/cc
#cp ~/secret/cc dd
#diff -s cc dd >/dev/null
#if [ "$?" == "1" ] ; then
#    #echo $?
#    echo "Test2 FAIL. (files not equal)"
#fi





