#!/bin/bash

function test_direct {
    #rm -f ~/.secrets/$1
    ../tools/bpenc2 -f -p 1234 test_data/$1 ~/.secrets/$1
    diff -q test_data/$1 ~/secrets/$1  # note the missing dot
    rm -f tmp/$1
    ../tools/bpdec2 -p 1234 ~/.secrets/$1 tmp/$1
    diff -q test_data/$1 tmp/$1
}

test_direct aa4096.txt

