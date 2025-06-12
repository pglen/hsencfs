#!/bin/sh

# Pack current project. Will back out from dir and create
# dirname-version.tgz

VER=`cat VERSION`
CURR=`pwd | awk -F '/' {'print $NF'} |  sort -n | tail -1`
#echo $CURR-$VER

if [ -f ../$CURR-$VER.tgz ] ; then
    echo "Already exists: ../$CURR-$VER.tgz ; Please delete first."
    exit 1
fi

SSS=`pwd`
cd ..
echo "Packing project $CURR-$VER"
tar cfz $CURR-$VER.tgz $CURR
cd $SSS
#mv ../$CURR-$VER.tgz .





