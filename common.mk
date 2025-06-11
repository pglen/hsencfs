# Common includes for sections

myincs =    -I$(srcdir)/../bluepoint -I$(srcdir)/../src \
            -I$(srcdir)/../common

cryptx =    ../bluepoint/hs_crypt.c     \
            ../bluepoint/bluepoint2.c

utilx =     ../common/hsutils.c ../common/base64.c \
            ../common/hspass.c ../common/xmalloc.c

# EOF