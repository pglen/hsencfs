# ------------------------------------------------------------------------
# HSENCFS source. (High Security Encrypted File system)

#include $(srcdir)/common.mk
include ../common.mk

AUTOMAKE_OPTIONS = subdir-objects

EXTRA_DIST = hsencfs

# Fuse based encrypted file system

bin_PROGRAMS =  hsencfs

# The main program
hsencfsdir = .

#-I$(srcdir)/../bluepoint -I$(srcdir)/../common

hsencfs_CFLAGS = -g -D_FILE_OFFSET_BITS=64 -O2 $(myincs)


hsencfs_SOURCES = hsencrr.c hsencrw.c hsencsb.c hsencsu.c hsencop.c \
                        $(utilx) $(cryptx) hsencfs.c

hsencfs_LDADD = -lfuse3 -lulockmgr  -lcrypto -lssl

clean-local:
	@-rm -f aa bb cc *~
	@-rm -f *.o
	@-rm -f hsencfs dualwrite zigzag zigjump

#clean:
#	@-rm -f  *~ *.o
#	@-rm -f dualwrite zigzag zigjump

# Help

#test-local:
#	@./create/create_all.sh
#	@./cycle/cycle_read.sh
#	@./cycle/cycle_write.sh
#

# EOF
