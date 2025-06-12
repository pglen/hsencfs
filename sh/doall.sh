#!/bin/bash

AA=`pwd`
#rm -f ../*.dsc ../*.deb ../*.changes ../*.build
rm  ../*

debuild -us -uc -S

cd ..
FF=`ls hsencfs_1.4.*_source.changes`
#echo "ff '$FF'"
debsign -k 286AE51BCCF9D1BEACA03BEDBE4FC066DA1ABD1F $FF
dput ppa:peterglen/ppa $FF

cd $AA
