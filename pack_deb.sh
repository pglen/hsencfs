#!/bin/bash

echo making deb package
rm -f html/*
rm -f latex/*
rm -f *.tar.gz
make dist-gzip
OOO=`ls *.tar.gz`

NNN=`./convname.py $OOO`
echo $NNN
mv $OOO ../$NNN

#debuild -S -us -uc

sudo dpkg-buildpackage -rfakeroot -D -B -us -uc