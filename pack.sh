#!/bin/sh

# Pack current project. Will back out from dir and create dirname.tgz
# and put it back to our dir.

VER=`cat VERSION`
CURR=`pwd | awk -F '/' {'print $NF'} |  sort -n | tail -1`
#echo $CURR-$VER
SSS=`pwd`
cd ..
echo "Packing project $CURR-$VER"
tar cfz $CURR-$VER.tgz $CURR
cd $SSS
mv ../$CURR-$VER.tgz .





