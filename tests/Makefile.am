# ------------------------------------------------------------------------
# HSENCFS source. (High Security Encrypted File system)

AUTOMAKE_OPTIONS = subdir-objects

# Fuse based encrypted file system, test utilities

bin_PROGRAMS =  dualwrite seekcp zigjump \
                zigzag farwrite onejump \
                dualread jumpread

dualwrite_SOURCES   = dualwrite.c
seekcp_SOURCES      = seekcp.c
zigjump_SOURCES     = zigjump.c
zigzag_SOURCES      = zigzag.c
farwrite_SOURCES    = farwrite.c
onejump_SOURCES     = onejump.c
dualread_SOURCES    = dualread.c
jumpread_SOURCES    = jumpread.c

clean-local:
	@-rm -f aa bb cc *~
	@-rm -f *.o
	@-rm -f hsencfs dualwrite zigzag zigjump

clean:
	@-rm -f  *~ *.o
	@-rm -f dualwrite zigzag zigjump

# Help

test-local:
	@./testall.sh
#	@./tests.sh
#	@./create/create_all.sh
#	@./cycle/cycle_read.sh
#	@./cycle/cycle_write.sh
#

#tests:
#	@./testall.sh

# EOF

