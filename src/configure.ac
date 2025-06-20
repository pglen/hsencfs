AC_PREREQ([2.68])
AC_INIT([hsencfs], [1.5.0], [peterglen99@gmail.com])
AM_INIT_AUTOMAKE([1.16.5 foreign])
AC_CONFIG_FILES([Makefile])

FUSEFLAGS="-D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=33 -I/usr/include/fuse3"

CPPFLAGS="$CPPFLAGS $USER_INCLUDES $FUSEFLAGS -D__STDC_FORMAT_MACROS"

CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS $USER_INCLUDES"
LDFLAGS="$LDFLAGS $PTHREAD_LIBS $USER_LDFLAGS"

AC_CHECK_LIB(fuse_ino64, fuse_new, [FUSE_LIBS="-lfuse_ino64"],
    [ AC_CHECK_LIB(fuse3, fuse_new, [FUSE_LIBS="-lfuse3"],
        [AC_MSG_ERROR([
            Can't find libfuse.a - install FUSE or add the search path to LDFLAGS
            and rerun configure, eg:
            export LDFLAGS=-L/usr/local/lib ])],)
    ],)

AC_CHECK_HEADER(fuse.h,,
    [AC_MSG_ERROR([
        Can't find fuse.h - install FUSE or add the search path to CPPFLAGS and
        rerun configure, eg:
        export CPPFLAGS=-I/usr/local/include ])])

# Checks for libraries.
#AC_CHECK_LIB([fuse], [fuse_main])
# FIXME: Replace `main' with a function in `-lulockmgr':
AC_CHECK_LIB([ulockmgr], [main])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PREFIX_DEFAULT(/usr)
AC_OUTPUT

# EOF
