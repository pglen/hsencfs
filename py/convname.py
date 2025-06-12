#!/usr/bin/env python3

import sys

if len (sys.argv) == 1:
    print("No filename")
    sys.exit(0)

#print(sys.argv[1])

first = str.split(sys.argv[1], "-")
second = str.split(first[1], ".tar")

print(first[0] + "_" + second[0] + ".orig.tar" + second[1] )

