# ------------------------------------------------------------------------
# HSENCFS tools. (High Security Encrypted File system)

AUTOMAKE_OPTIONS = subdir-objects
#SUBDIRS = src tools, common, bluepoint

# Fuse based encrypted file system, test utilities

bin_PROGRAMS =  bpdec2 bpenc2

bpenc2dir = .
bpenc2_SOURCES  = bpenc2.c  bp2com.c  ../common/hsutils.c ../common/hspass.c \
                       ../bluepoint/hs_crypt.c  ../bluepoint/hs_crypt.h  \
                              ../bluepoint/bluepoint2.c ../bluepoint/bluepoint2.h

bpenc2_CFLAGS   =  -I$(srcdir)/../bluepoint -I$(srcdir)/../common
bpenc2_DEPENDENCIES =

bpdec2dir = .
bpdec2_SOURCES  = bpdec2.c bp2com.c ../common/hsutils.c ../common/hspass.c  \
                       ../bluepoint/hs_crypt.c  ../bluepoint/hs_crypt.h  \
                              ../bluepoint/bluepoint2.c ../bluepoint/bluepoint2.h

bpdec2_CFLAGS   =  -I$(srcdir)/../bluepoint -I$(srcdir)/../common
bpdec2_DEPENDENCIES =

clean:
	@-rm -f aa bb cc dd ee .*.secret *.o  > /dev/null 2>&1

test:
	@echo "hello" > aa
	@./bpenc2 -f -p 1234 aa bb
	@./bpdec2 -f -p 1234 bb cc
	@echo diff should stay silent
	@diff aa cc










