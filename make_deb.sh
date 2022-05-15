#!/bin/bash

#make_deb.sh

RR=hsencfs
NN=hsencfs_1.4.0_x86_64

mkdir -p $NN
mkdir -p $NN/DEBIAN
mkdir -p $NN/usr/bin
mkdir -p $NN/etc

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
Pre-Depends: libc6 (>= 2.0.105)
Provides: hsencfs
Description: High Security Encrypted File System; Inline encryption filesystem.
EOF

cat <<EOF > $NN/usr/bin/mypackage
#!/bin/bash
echo this is my package
EOF

cp -a src/hsencfs $NN/usr/bin/
chmod 755 $NN/usr/bin/hsencfs

cat <<EOF >> $NN/DEBIAN/postinst
#!/bin/bash
touch /root/touched
EOF

chmod 755 $NN/DEBIAN/postinst

dpkg-deb -b hsencfs_1.4.0_x86_64/




