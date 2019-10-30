dnl ***************************
dnl *** Initialize autoconf ***
dnl ***************************
AC_INIT([gooroom-security-status-tools], [0.1.0])
AC_PREREQ(2.63)

dnl ***********************
dnl Initialize automake ***
dnl ***********************
AM_INIT_AUTOMAKE([1.8 dist-xz no-dist-gzip foreign])
AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE()
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

dnl *******************************
dnl *** Check for UNIX variants ***
dnl *******************************
#AC_AIX()
#AC_ISC_POSIX()
#AC_MINIX()

dnl **************************
dnl -- check for GSettings
dnl **************************
GLIB_GSETTINGS

dnl ********************************
dnl *** Check for basic programs ***
dnl ********************************
AC_PROG_CC()
AM_PROG_CC_C_O()
AC_PROG_LD()
AC_PROG_INSTALL()
IT_PROG_INTLTOOL([0.35.2])

dnl **************************
dnl *** Initialize libtool ***
dnl **************************
LT_PREREQ([2.4])
LT_INIT([disable-static])

dnl **********************************
dnl *** Check for standard headers ***
dnl **********************************
AC_HEADER_STDC()
AC_CHECK_HEADERS([stdlib.h string.h errno.h unistd.h])

dnl ******************************
dnl *** Check for i18n support ***
dnl ******************************
GETTEXT_PACKAGE=gooroom-security-status-tools
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE", [Gettext Package])
AM_GLIB_GNU_GETTEXT

dnl ***********************************
dnl *** Check for required packages ***
dnl ***********************************
PKG_CHECK_MODULES(GTK3, gtk+-3.0 >= 3.20.0)
PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.44.0)
PKG_CHECK_MODULES(GIO, gio-2.0 >= 2.58.3)
PKG_CHECK_MODULES(JSON_C, json-c)
PKG_CHECK_MODULES(POLKIT, polkit-gobject-1 >= 0.103)

AC_OUTPUT([
  Makefile
  data/Makefile
  common/Makefile
  src/Makefile
  src/sysinfo/Makefile
  src/settings/Makefile
  po/Makefile.in
])
