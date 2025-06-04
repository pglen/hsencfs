# ------------------------------------------------------------------------
# HSENCFS source. (High Security Encrypted File system)

AUTOMAKE_OPTIONS = subdir-objects

EXTRA_DIST = hsencfs

# Fuse based encrypted file system, test utilities

bin_PROGRAMS =  hsencfs

#tests/dualwrite tests/seekcp tests/zigjump tests/zigzag tests/farwrite
#tests/onejump tests/dualread tests/jumpread
#hsaskpass

# The main program
hsencfsdir = .

hsencfs_CFLAGS = -g -D_FILE_OFFSET_BITS=64 -O2 -I$(srcdir)/../bluepoint \
            -I$(srcdir)/../common

#-lfuse3  -lcrypto -lssl

hsencfs_SOURCES = hsencfs.c hsencrr.c hsencrw.c hsencsb.c hsencsu.c base64.c \
                        ../common/hsutils.c ../common/hspass.c \
                            ../bluepoint/bluepoint2.c ../bluepoint/bluepoint2.h \
                                 ../bluepoint/hs_crypt.c  ../bluepoint/hs_crypt.h

hsencfs_LDADD = -lfuse3 -lulockmgr  -lcrypto -lssl

#hsencfs_DEPENDENCIES  =

clean-local:
	@-rm -f aa bb cc
	@-rm -f *.obj
	@-rm -f hsencfs dualwrite zigzag zigjump

# Help

#test-local:
#	@./create/create_all.sh
#	@./cycle/cycle_read.sh
#	@./cycle/cycle_write.sh
#




















