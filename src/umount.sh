#!/bin/bash
aa=`mount | grep secret`
if [ "$aa" != "" ] ; then
    fusermount -u ~/secret
fi






