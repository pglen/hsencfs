# ------------------------------------------------------------------------
# HSENCFS tools. (High Security Encrypted File system)

AUTOMAKE_OPTIONS = subdir-objects

# Fuse based encrypted file system, test utilities

EXTRA_DIST =  hsutils.c  hspass.c

noinst_PROGRAMS = hsaskpass

# Password helper

hsaskpassdir = .

hsaskpass_CFLAGS = -D_FILE_OFFSET_BITS=64 -O2 -I$(srcdir)/bluepoint
hsaskpass_LDADD = -lulockmgr -lfuse3  -lcrypto -lssl
hsaskpass_SOURCES = hsaskpass.c hsutils.c hspass.c ../bluepoint/bluepoint2.c

#clean-local:
#	@-rm -f aa bb cc *.o  > /dev/null 2>&1
#	@-rm -f bpenc2 bpdec2

clean:
	@-rm -f aa bb cc *.o  > /dev/null 2>&1
	@-rm -f bpenc2 bpdec2

# EOF
