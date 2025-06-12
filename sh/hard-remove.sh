#!/bin/bash

# Use to remove all traces of HSENCFS. This bypasses normal installation
# procedures. Developers only.

HS_ALL_EXE="\
                hsaskpass               \
                hsaskpass.py            \
                hsencfs                 \
                hstray.py               \
"

HS_ALL_DOC="\
                hsencfs/FUSEOPTS        \
                hsencfs/PASSES          \
                hsencfs/QUICKSTART      \
                hsencfs/SECURITY        \
                hsencfs/hsencfs.init    \
                hsencfs/hsencfs.spec    \
                hsencfs.info.gz         \
                man1/hsencfs.1.gz       \
"
for aa  in $HS_ALL_EXE  ; do
    rm -f "/usr/bin/$aa"
    rm -f  "/usr/local/bin/$aa"
done

for aa  in $HS_ALL_DOC  ; do
    rm -f "/usr/share/$aa"
    rm -f "/usr/local/share/$aa"
    rm -f "/usr/local/share/doc/$aa"
done

rm -f /usr/lib/bonobo/servers/GNOME_HSENCApplet.server
rm -f /usr/local/share/pixmaps/hspadlock.png
rm -f /usr/local/share/pixmaps/hsicon.png
rm -f /usr/share/pixmaps/hspadlock.png
rm -f /usr/share/pixmaps/hsicon.png

# EOF
