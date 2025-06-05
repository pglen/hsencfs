#!/bin/bash

pushd `pwd`

cd ~/secrets
make distclean
./configure
make
ERR=$?
popd

echo Make error: $ERR
