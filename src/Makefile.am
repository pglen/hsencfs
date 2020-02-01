# ------------------------------------------------------------------------
# HSENCFS tools. (High Security Encrypted File system)

# Fuse based encrypted file system, test utilities

bin_PROGRAMS =  hsencfs
#hsaskpass

# The main program
hsencfsdir = .
hsencfs_CFLAGS = -D_FILE_OFFSET_BITS=64 -O2 -I$(srcdir)/bluepoint \
            -lfuse -lulockmgr -I$(srcdir)/../common

hsencfs_SOURCES = hsencfs.c base64.c ../common/hsutils.c ../common/hspass.c \
                        ../bluepoint/bluepoint2.c

#hsencfs_LDADD   = ../bluepoint/bluepoint2.o
#../common/hsutils.o
#                    ../common/hspass.o

# Password helper
hsaskpass_CFLAGS = -D_FILE_OFFSET_BITS=64 -O2 -I$(srcdir)/bluepoint

clean-local:
	@-rm -f aa bb cc *.o  > /dev/null 2>&1
#	@-rm -f bpenc2 bpdec2












