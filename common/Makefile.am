libcommon_la_CPPFLAGS = \
	-I$(top_srcdir)/common \
	-DGOOROOM_LOGPARSER_SEEKTIME_HELPER=\"$(pkglibexecdir)/gooroom-logparser-seektime-helper\" \
	-DGOOROOM_SECURITY_LOGPARSER_WRAPPER=\"$(pkglibexecdir)/gooroom-security-logparser-wrapper\" \
	$(AM_CPPFLAGS)

noinst_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES =	\
	common.h \
	common.c

libcommon_la_CFLAGS = \
	$(GLIB_CFLAGS)	\
	$(POLKIT_CFLAGS)	\
	$(JSON_C_CFLAGS)

libcommon_la_LDFLAGS = \
	$(AM_LDFLAGS)


libcommon_la_LIBADD = \
	$(GLIB_LIBS)	\
	$(POLKIT_LIBS)	\
	$(JSON_C_LIBS)

pkglibexec_PROGRAMS = gooroom-systemd-control-helper

gooroom_systemd_control_helper_SOURCES = gooroom-systemd-control-helper.c
gooroom_systemd_control_helper_CFLAGS = $(GIO_CFLAGS)
gooroom_systemd_control_helper_LDFLAGS = $(GIO_LIBS)

DISTCLEANFILES = Makefile.in
