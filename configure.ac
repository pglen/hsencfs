#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#

AC_PREREQ([2.68])
AC_INIT([hsencfs], [1.5.0], [peterglen99@gmail.com])
AM_INIT_AUTOMAKE([]) #1.16.5 foreign])
AC_CONFIG_SUBDIRS([ bluepoint common src ])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])

AM_CONDITIONAL([AUTOCHECK_DEFINED], [test x"$AUTOCHECK" != x""])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

AC_PREFIX_DEFAULT(/usr)

SERVICE_FILE=systemd/hsencfs.service
SYSTEMD_DIR=`pkg-config systemd --variable=systemdsystemunitdir`

#AC_CONFIG_COMMANDS_POST([cp "$SERVICE_FILE" "$SYSTEMD_DIR"])
#AC_CONFIG_COMMANDS_POST([systemctl enable "$SYSTEMD_DIR/$SERVICE_FILE"])
#AC_CONFIG_COMMANDS_POST([systemctl start "$SERVICE_FILE"])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_MAKE_SET

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

AC_CHECK_HEADER([openssl/ssl.h], [], [AC_MSG_ERROR([Missing required header: openssl/ssl.h.])])
AC_CHECK_LIB(ssl, OPENSSL_init_ssl, [FOUND_SSL_LIB="yes"], [AC_MSG_ERROR([Missing required lib: openssl/ssl.h.])])
AC_CHECK_LIB(crypto, CRYPTO_new_ex_data, [FOUND_CRYPTO_LIB="yes"], [AC_MSG_ERROR([library 'crypto' is required for OpenSSL])])

# Set OpenSSL flags
AC_DEFINE(HAVE_OPENSSL, 1, [Define to 1 if OpenSSL is available])

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([clock_gettime dup2 fdatasync ftruncate getcwd getpass lchown memset mkdir mkfifo rmdir strstr strtol])

AC_CONFIG_FILES([Makefile
                 bluepoint/Makefile
                 common/Makefile
                 src/Makefile
                 docs/Makefile
                 systemd/Makefile])

PKG_PROG_PKG_CONFIG
AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [systemd])],,
     [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
   [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
    [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
    with_systemdsystemunitdir=no],
   [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])

AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

AC_OUTPUT














