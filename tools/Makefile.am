# ------------------------------------------------------------------------
# HSENCFS tools. (High Security Encrypted File system)

# Fuse based encrypted file system, test utilities

bin_PROGRAMS =  bpdec2 bpenc2

bpdec2dir = .
bpdec2_SOURCES  = bpdec2.c
bpdec2_LDADD    = ../bluepoint/bluepoint2.o 
bpdec2_CFLAGS   =  -I$(srcdir)/../bluepoint
bpdec2_DEPENDENCIES =  

bpenc2dir = .
bpenc2_SOURCES  = bpenc2.c
bpenc2_LDADD    = ../bluepoint/bluepoint2.o 
bpenc2_CFLAGS   =  -I$(srcdir)/../bluepoint
bpenc2_DEPENDENCIES =  

clean:
	@-rm -f aa bb cc *.o  > /dev/null 2>&1
#	@-rm -f bpenc2 bpdec2






