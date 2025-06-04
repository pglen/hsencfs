# ------------------------------------------------------------------------
# Bluepoint encryption for HSENCFS
# (High Security Encrypted File system)

AUTOMAKE_OPTIONS = subdir-objects

EXTRA_DIST = bluepoint.c bluepoint.h hs_crypt.c hs_crypt.h

noinst_PROGRAMS = test_blue2 block_blue2
test_blue2_CFLAGS = -g -D_FILE_OFFSET_BITS=64
block_blue2_CFLAGS = -g -D_FILE_OFFSET_BITS=64

test_blue2dir = .
test_blue2_SOURCES  = bluepoint2.c test_blue2.c bluepoint2.h bluemac.h  hs_crypt.c

block_blue2dir = .
block_blue2_SOURCES  = bluepoint2.c block_blue2.c bluepoint2.h bluemac.h hs_crypt.c

test:
	./test_blue2

clean-local:
	@-rm -f *.o

clean:
	@-rm -f *.o












