#!/bin/bash

find . -type f | grep -E -v "study/|tests/|garbage/" | \
        grep -E ".*.sh$|.*\.[ch]$" | \
            xargs -i grep -EH "$1" {}
