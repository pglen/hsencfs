#!/bin/bash
echo Test compiling
pushd `pwd`
cd ~/secrets
./configure
ERR=$?
popd
echo Test compiling done err=$ERR

