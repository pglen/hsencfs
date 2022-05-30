#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([hsencfs], [1.20], [bugs@nohost.none])
AC_CONFIG_SRCDIR([src/hsencop.c])
AC_CONFIG_SUBDIRS([src tools])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

AC_PREFIX_DEFAULT(/usr/local)

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_MAKE_SET

FUSEFLAGS="-D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26"
CPPFLAGS="$CPPFLAGS $USER_INCLUDES $FUSEFLAGS -D__STDC_FORMAT_MACROS"
CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS $USER_INCLUDES"
LDFLAGS="$LDFLAGS $PTHREAD_LIBS $USER_LDFLAGS"

AC_CHECK_HEADER(fuse.h,,
    [AC_MSG_ERROR([
        Can't find fuse.h - install FUSE or add the search path to CPPFLAGS and
        rerun configure, eg:
        export CPPFLAGS=-I/usr/local/include ])])

AC_CHECK_LIB(fuse_ino64,fuse_new, [FUSE_LIBS="-lfuse_ino64"],
    [ AC_CHECK_LIB(fuse,fuse_new, [FUSE_LIBS="-lfuse"],
        [AC_MSG_ERROR([
            Can't find libfuse.a - install FUSE or add the search path to LDFLAGS
            and rerun configure, eg:
            export LDFLAGS=-L/usr/local/lib ])],)
    ],)

# Checks for libraries.
AC_CHECK_LIB([fuse], [fuse_main])
# FIXME: Replace `main' with a function in `-lulockmgr':
AC_CHECK_LIB([ulockmgr], [main])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h sys/time.h syslog.h unistd.h])

# We clear the CFLAGS mainly to prevent debugging information to be genetared
# automatically. As this is a security program, this default is more
# reasonable. Comment out the line below for debug info. (or start configure
# with appropiate options).
CFLAGS=

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([clock_gettime dup2 fdatasync ftruncate getcwd getpass lchown memset mkdir mkfifo rmdir strstr strtol])

AC_CONFIG_FILES([Makefile
                 bluepoint/Makefile
                 tools/Makefile
                 docs/Makefile]
                 )
AC_OUTPUT








