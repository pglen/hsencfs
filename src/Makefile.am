# ------------------------------------------------------------------------
# HSENCFS tools. (High Security Encrypted File system)

# Fuse based encrypted file system, test utilities

bin_PROGRAMS =  hsencfs
#hsaskpass

# The main program
hsencfsdir = .

hsencfs_CFLAGS = -g -D_FILE_OFFSET_BITS=64 -O2 -I$(srcdir)/bluepoint \
            -I$(srcdir)/../common

hsencfs_SOURCES = hsencfs.c base64.c ../common/hsutils.c ../common/hspass.c \
                        ../bluepoint/bluepoint2.c

hsencfs_LDADD = -lulockmgr -lfuse3

# Password helper
hsaskpass_CFLAGS = -D_FILE_OFFSET_BITS=64 -O2 -I$(srcdir)/bluepoint

clean-local:
	@-rm -f aa bb cc
	@-rm -f *.obj

# Help

test-local:
	@./create/create_all.sh
	@./cycle/cycle_read.sh
	@./cycle/cycle_write.sh





















