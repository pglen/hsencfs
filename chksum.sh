#!/bin/bash

# Verify the integrity of our archive

echo -n "Checking checksum file ... "
sha1sum --check --quiet SUMFILE
echo Done

echo -n "Checking checksums ... "
sha1sum --check --quiet sha1.sum
echo Done
