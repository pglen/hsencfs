#!/bin/bash

. ./vars.sh

fusermount -u ~/secrets

./hsencfs -q -l 4 -p $PASS ~/secrets ~/.secrets

cp test/testfile ~/secrets/testfile.enc
cp ~/secrets/testfile.enc test/testfile.dec

diff test/testfile test/testfile.dec

fusermount -u ~/secrets







