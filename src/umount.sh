#!/bin/bash
aa=`mount | grep secrets`
if [ "$aa" != "" ] ; then
    fusermount -u ~/secrets
fi







