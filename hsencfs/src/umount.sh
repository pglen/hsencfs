#!/bin/bash

. ./vars.sh

aa=`mount | grep secrets`
if [ "$aa" != "" ] ; then
    fusermount3 -u $DROOT
fi







