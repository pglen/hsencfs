#!/bin/bash

echo Do not use, obsoleted by debmake
exit

# This shell script is responsible to create a binary distribution .deb file

RR=hsencfs
NN=hsencfs_1.4.0_x86_64

mkdir -p $NN
mkdir -p $NN/DEBIAN
mkdir -p $NN/usr/bin
mkdir -p $NN/usr/share/man/man1
mkdir -p $NN/etc

# Generate fresh copy
rm -rf $NN/usr/bin/*
rm -rf $NN/etc/*

touch $NN/DEBIAN/control
touch $NN/etc/$RR.conf

cat <<EOF > $NN/DEBIAN/control
Package: hsencfs
Essential: no
Priority: optional
Section: base
Maintainer: Peter Glen <peterglen99@gmail.com>
Architecture: amd64
Version: 1.4-0
Pre-Depends: fuse, fuse3
Provides: hsencfs
Description: High Security Encrypted File System; Inline encryption filesystem.
EOF

function to_bin {
    cp -a $1/$2 $NN/usr/bin/
    chmod 755 $NN/usr/bin/$2
}

to_bin src hsencfs
to_bin . hsaskpass.py
to_bin . mountsecrets.sh

function to_man {
    cp -a $1/$2 $NN/usr/share/man/man1
    chmod 755 $NN/usr/share/man/man1/$2
}

to_man docs hsencfs.1
to_man docs hsencfs.info

cat <<EOF >> $NN/DEBIAN/postinst
#!/bin/bash
touch /root/touched
EOF

chmod 755 $NN/DEBIAN/postinst

dpkg-deb -b hsencfs_1.4.0_x86_64/

# EOF
