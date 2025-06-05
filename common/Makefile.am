# ------------------------------------------------------------------------
# HSENCFS tools. (High Security Encrypted File system)

AUTOMAKE_OPTIONS = subdir-objects

# Fuse based encrypted file system

noinst_PROGRAMS = testpass

# Password helper

testpassdir = .

testpass_CFLAGS = -D_FILE_OFFSET_BITS=64 -O2 -I$(srcdir)/bluepoint
testpass_LDADD = -lulockmgr -lfuse3  -lcrypto -lssl
testpass_SOURCES = testpass.c hsutils.c hspass.c \
          ../bluepoint/bluepoint2.c ../src/base64.c


bin_PROGRAMS =  bpdec2 bpenc2

# Was in the tools directory

bpenc2dir = .
bpenc2_SOURCES  = bpenc2.c  bp2com.c  ../common/hsutils.c \
                        ../common/hspass.c        \
                        ../bluepoint/hs_crypt.c   \
                        ../bluepoint/hs_crypt.h   \
                        ../bluepoint/bluepoint2.c \
                        ../bluepoint/bluepoint2.h

bpenc2_CFLAGS   =  -g -D_FILE_OFFSET_BITS=64  -I$(srcdir)/../bluepoint \
                 -I$(srcdir)/../common -lssl -lcrypt
bpenc2_DEPENDENCIES =

bpenc2_LDADD = -lulockmgr -lfuse3  -lcrypto -lssl

bpdec2dir = .
bpdec2_SOURCES  = bpdec2.c bp2com.c ../common/hsutils.c ../common/hspass.c  \
                       ../bluepoint/hs_crypt.c  ../bluepoint/hs_crypt.h  \
                              ../bluepoint/bluepoint2.c ../bluepoint/bluepoint2.h

bpdec2_CFLAGS   =  -g -D_FILE_OFFSET_BITS=64 -I$(srcdir)/../bluepoint \
                     -lssl -lcrypt -I$(srcdir)/../common
bpdec2_DEPENDENCIES =
bpdec2_LDADD = -lulockmgr -lfuse3  -lcrypto -lssl


#clean-local:
#	@-rm -f aa bb cc *.o  > /dev/null 2>&1
#	@-rm -f bpenc2 bpdec2

clean:
	@-rm -f aa bb cc *.o *~ > /dev/null 2>&1
	@-rm -f bpenc2 bpdec2

# EOF
