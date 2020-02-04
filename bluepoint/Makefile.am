# ------------------------------------------------------------------------
# Bluepoint encryption for HSENCFS
# (High Security Encrypted File system)

EXTRA_DIST = bluepoint.c bluepoint.h hs_crypt.c

noinst_PROGRAMS = test_blue2 block_blue2

test_blue2dir = .
test_blue2_SOURCES  = bluepoint2.c test_blue2.c bluepoint2.h bluemac.h

block_blue2dir = .
block_blue2_SOURCES  = bluepoint2.c block_blue2.c bluepoint2.h bluemac.h

test:
	./test_blue2

clean:
	@-rm -f *.o











