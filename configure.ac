#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([skunk], [0.9.0], [vivekrjg@gmail.com])
AC_CONFIG_SRCDIR([PFSender.h])
AM_INIT_AUTOMAKE([skunk], [0.9.0] )

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([ncurses], [newwin],
	[ echo "ncurses ok" ],
	[ echo "Missing ncurses-devel required to build"; exit -1 ] )
AC_CHECK_LIB([pcap], [pcap_next_ex],
	[ echo "libpcap ok" ],
	[ echo "Missing libpcap-devel required to build"; exit -1 ] )

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netinet/in.h stdlib.h string.h sys/ioctl.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MKTIME

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
