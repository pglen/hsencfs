# ------------------------------------------------------------------------
# HSENCFS tools. (High Security Encrypted File system)

# Fuse based encrypted file system, test utilities

bin_PROGRAMS =  hsencfs hsaskpass

# The main program
hsencfsdir = .
hsencfs_CFLAGS = -D_FILE_OFFSET_BITS=64 -O2 -I$(srcdir)/bluepoint \
            -lfuse -lulockmgr

hsencfs_SOURCES = hsencfs.c hsutils.c hspass.c hsutils.h
hsencfs_LDADD = ../bluepoint/bluepoint2.o

# Password helper
hsaskpass_CFLAGS = -D_FILE_OFFSET_BITS=64 -O2 -I$(srcdir)/bluepoint

clean:
	@-rm -f aa bb cc *.o  > /dev/null 2>&1
#	@-rm -f bpenc2 bpdec2







