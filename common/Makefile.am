# ------------------------------------------------------------------------
# HSENCFS tools. (High Security Encrypted File system)

AUTOMAKE_OPTIONS = subdir-objects

# Fuse based encrypted file system

noinst_PROGRAMS = testpass

# Password helper

testpassdir = .

myincs =    -I$(srcdir)/../bluepoint -I$(srcdir)/../src \
            -I$(srcdir)/../common
cryptx =    ../bluepoint/hs_crypt.c     \
            ../bluepoint/bluepoint2.c

testpass_CFLAGS = -D_FILE_OFFSET_BITS=64 -O2  $(myincs)
testpass_LDADD = -lulockmgr -lfuse3  -lcrypto -lssl
testpass_SOURCES = testpass.c hsutils.c hspass.c base64.c \
                    $(cryptx)

bin_PROGRAMS =  bpdec2 bpenc2

#bpenc2dir = .
bpenc2_SOURCES  = bpenc2.c  bp2com.c hsutils.c      \
                            base64.c hspass.c       \
                            $(cryptx)

bpenc2_CFLAGS   =  -g -D_FILE_OFFSET_BITS=64  $(myincs) \
                            -lssl -lcrypt

bpenc2_DEPENDENCIES =

bpenc2_LDADD = -lulockmgr -lfuse3  -lcrypto -lssl

#bpdec2dir = .
bpdec2_DEPENDENCIES =

bpdec2_SOURCES  =       bpdec2.c bp2com.c base64.c   \
                        hsutils.c hspass.c  \
                        $(cryptx)

bpdec2_CFLAGS = -g -D_FILE_OFFSET_BITS=64 $(myincs)  \
                     -lssl -lcrypt
bpdec2_LDADD = -lulockmgr -lfuse3  -lcrypto -lssl

#clean-local:
#	@-rm -f aa bb cc *.o  > /dev/null 2>&1
#	@-rm -f bpenc2 bpdec2

clean:
	@-rm -f aa bb cc *.o *~ > /dev/null 2>&1
	@-rm -f bpenc2 bpdec2

# EOF
