#!/bin/bash

. ./vars.sh

aa=`mount | grep secrets`
if [ "$aa" != "" ] ; then
    fusermount -u $DROOT
fi








