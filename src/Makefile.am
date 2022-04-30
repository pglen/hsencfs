# ------------------------------------------------------------------------
# HSENCFS tools. (High Security Encrypted File system)

# Fuse based encrypted file system, test utilities

bin_PROGRAMS =  hsencfs \
tests/dualwrite tests/seekcp tests/zigjump tests/zigzag tests/farwrite \
tests/onejump tests/dualread

#hsaskpass

# The main program
hsencfsdir = .

hsencfs_CFLAGS = -g -D_FILE_OFFSET_BITS=64 -O2 -I$(srcdir)/../bluepoint \
            -I$(srcdir)/../common

hsencfs_SOURCES = hsencfs.c hsencrr.c hsencrw.c hsencsb.c hsencsu.c base64.c \
                        ../common/hsutils.c ../common/hspass.c \
                            ../bluepoint/bluepoint2.c ../bluepoint/bluepoint2.h \
                                 ../bluepoint/hs_crypt.c  ../bluepoint/hs_crypt.h

#hsencfs_DEPENDENCIES  =

hsencfs_LDADD = -lulockmgr -lfuse3

# Password helper
hsaskpass_CFLAGS = -D_FILE_OFFSET_BITS=64 -O2 -I$(srcdir)/bluepoint

clean-local:
	@-rm -f aa bb cc
	@-rm -f *.obj
	@-rm -f hsencfs dualwrite zigzag zigjump

# Help

test-local:
	@./create/create_all.sh
	@./cycle/cycle_read.sh
	@./cycle/cycle_write.sh





















