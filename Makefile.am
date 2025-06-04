# ------------------------------------------------------------------------
# HSENCFS (High Security EnCrypting File System)
# Fuse based encrypted file system.
# It will encrypt data on write, decrypt data on read.
#

SUBDIRS = common bluepoint src . tools docs systemd

PAN_SERV=GNOME_HSENCApplet.server
BONOBO_DIR=/usr/lib/bonobo/servers

# Docs for distribution
dist_doc_DATA = PASSES FUSEOPTS QUICKSTART SECURITY PASSHINTS DISCLAIMER\
        hsencfs.spec hsencfs.init compall.sh hard-remove.sh \
            lazy.sh

#                $(PAN_SERV).in

# Scripts for askpass and tray
dist_bin_SCRIPTS =                  \
        hsaskpass.py                \
        hstray.py

# Auxiliaries
#EXTRA_DIST = src/hsencrw.c src/hsencop.c
#EXTRA_DIST += common/hspass.c common/hsutils.c
#EXTRA_DIST += images/hsicon.png images/hsicon.svg images/hspadlock.png \
#                    images/hspadlock.svg images/screenshot.png
##EXTRA_DIST += study
#EXTRA_DIST  += hsaskpass.py hsaskpass.sh

# Fake it into the distribution
# use: ls *.py *.sh *.server SUMFILE sha*

#GNOME_HSENCApplet.server.in

EXTRA_DIST =                       \
        checksum.sh                 \
        enctest.sh                  \
        gensum.sh                   \
        lazy.sh                     \
        sha1.sum                    \
        SUMFILE

#check:
#    # Create new folder, destroy at end. Good example of installation-less
#    # creation of a secret folder with the force option
#	@./src/hsencfs -q -l 2 -f -p 1234 ~/.testdata ~/testsecrets
#	@-$(srcdir)/enctest.sh
#	@-fusermount -u ~/testsecrets
#	@-rm -rf ~/testsecrets ~/.testdata

#clean-local:
#	@-chmod -R u+w src/hsencfs-*   > /dev/null 2>&1
#	@-rm -rf src/hsencfs-*.rpm     > /dev/null 2>&1
#	@-rm -rf src/hsencfs-*.tar.gz  > /dev/null 2>&1
#	@-rm -f $(PAN_SERV)

#	@-chmod -R u+w src/hsencfs-*   > /dev/null 2>&1
#	@-rm -rf src/hsencfs-*.rpm     > /dev/null 2>&1
#	@-rm -rf src/hsencfs-*.tar.gz  > /dev/null 2>&1
#	@-rm -f $(PAN_SERV)

# We are forcing this to go to /usr/lib as panel will look for it there
# 1.) Generate correct .server file for current bin 2.) Put it in bonobo lib dir
# Allow failure without terminating the build. This is because the distcheck
# will fail on tying to create bonobo files, but it is not an error to fail
# in user mode creating a system file.

#cat $(srcdir)/$(PAN_SERV).in | \
#        sed s%HSTRAY_BIN%$(bindir)/hstray.py% > $(top_builddir)/$(PAN_SERV)

#	-$(INSTALL) $(top_builddir)/$(PAN_SERV) $(BONOBO_DIR)

install-data-local:
	-$(mkinstalldirs) $(BONOBO_DIR)
	$(mkinstalldirs) $(DESTDIR)/$(datarootdir)/pixmaps

#	$(INSTALL) $(srcdir)/hsicon.png  $(DESTDIR)/$(datarootdir)/pixmaps
#	$(INSTALL) $(srcdir)/hspadlock.png $(DESTDIR)/$(datarootdir)/pixmaps

uninstall-local:
	-rm -f $(top_builddir)/$(PAN_SERV)
	-rm -f $(BONOBO_DIR)/$(PAN_SERV)

#	-rm -f $(DESTDIR)/$(datarootdir)/pixmaps/hsicon.png
#	-rm -f $(DESTDIR)/$(datarootdir)/pixmaps/hspadlock.png

gensum:
	-./gensum.sh

# Make RPMS. To run on an older system, the RPM subsystem needed patching.
# We patched the files as follows:
#
# 1.) Added redirect (>>rpmwarn) to /usr/lib/rpm/check-files.sh
# The check delivers a warning instead of an error. Context:
#
# while read f; do
#   echo $f | sed -e "s#^$RPM_BUILD_ROOT#   #g" >> rpmwarn
# done
#
# 2.) Commented out strict=true line in /usr/lib/rpm/find-debuginfo.sh
# The check delivers a warning instead of an error.  Context:
#
# while [ $# -gt 0 ]; do
#  case "$1" in
#  --strict-build-id)
#    #strict=true
#    ;;
#
# All this was necessary to allow both RPM build and distcheck to pass.

rpm: rpm-src rpm-bin

rpm-src:  dist
	rpmbuild -ts hs*.tar.gz
	-cp ~/rpmbuild/SOURCES/hsenc*.rpm $(top_builddir)
	@echo  "*******************************************"
	@echo  Done RPM SRC Creation. SRPM in current dir
	@echo  "*******************************************"

rpm-bin:  dist
	rpmbuild -tb *.tar.gz
	-cp ~/rpmbuild/RPMS/`uname -m`/hsenc*.rpm $(top_builddir)
	@echo  "*******************************************"
	@echo  Done RPM Creation. RPM in current dir
	@echo  "*******************************************"

# Execute the whole creation / check / packaging cycle
cycle: gensum dist distcheck rpm
	@echo
	@echo  "***************"
	@echo  Done Cycle Check.
	@echo  "***************"

# Use only for testing / development. Will hard erase all of HSENC.
hard-remove:
	$(srcdir)/hard-remove.sh

# Wanted to look ... you may be curious too. Just add as a dependency.
test-vars:
	@echo  top_builddir=$(top_builddir)
	@echo  dc_install_base=$$dc_install_base
	@echo  dc_destdir=$(dc_destdir)
	@echo  DESTDIR=$(DESTDIR)
	@echo  bindir=$(bindir)
	@echo  srcdir=$(srcdir)
	@echo  prefix=$(prefix)

#	if $(AUTOCHECK_DEFINED)
#	AUTOCHECK="autocheck"
#	endif
# make clean

git:
	git add .
	git commit -m autocheck
	git push

#clean:
#	@-rm -f *.old

#if HAVE_SYSTEMD
#SYSTEMD_DIR_DATA = \
#  hsencfs.service
#endif

