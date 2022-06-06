#!/bin/bash

AA=`pwd`
#rm -f ../*.dsc ../*.deb ../*.changes ../*.build
rm  ../*

debuild -us -uc -S

cd ..

debsign -k 286AE51BCCF9D1BEACA03BEDBE4FC066DA1ABD1F hsencfs_1.4.*_source.changes
dput ppa:peterglen/ppa hsencfs_1.4.*_source.changes

cd $AA
