#!/bin/bash

. ./vars.sh

#echo $PASS $DROOT

./hsencfs  -l 4 -p $PASS $DROOT
RET=$?
if [ "$RET" != "0" ] ; then
    echo hsencfs returned $RET
fi






