gooroom_security_status_settings_CPPFLAGS = \
	-I$(top_srcdir)/common	\
	-DLOCALEDIR=\"$(localedir)\"	\
	-DGCSR_WRAPPER=\"$(pkglibexecdir)/gooroom-client-server-register-wrapper\" \
	-DGOOROOM_SYSTEMD_CONTROL_HELPER=\"$(pkglibexecdir)/gooroom-systemd-control-helper\" \
	$(AM_CPPFLAGS)

bin_PROGRAMS = gooroom-security-status-settings

BUILT_SOURCES = \
	settings-resources.c \
	settings-resources.h

gooroom_security_status_settings_SOURCES = \
	$(BUILT_SOURCES)	\
	main.c	\
	settings-window.h	\
	settings-window.c

gooroom_security_status_settings_CFLAGS =  \
	$(GLIB_CFLAGS)	\
	$(GTK3_CFLAGS)

gooroom_security_status_settings_LDFLAGS = \
	$(AM_LDFLAGS)

gooroom_security_status_settings_LDADD =   \
	$(GLIB_LIBS)	\
	$(GTK3_LIBS)	\
	$(top_builddir)/common/libcommon.la

resource_files = $(shell glib-compile-resources --sourcedir=$(srcdir) --generate-dependencies $(srcdir)/gresource.xml)
settings-resources.c: gresource.xml $(resource_files)
	$(AM_V_GEN) glib-compile-resources --target=$@ --sourcedir=$(srcdir) --generate-source --c-name settings $<
settings-resources.h: gresource.xml $(resource_files)
	$(AM_V_GEN) glib-compile-resources --target=$@ --sourcedir=$(srcdir) --generate-header --c-name settings $<


@INTLTOOL_DESKTOP_RULE@
desktopdir = $(datadir)/applications
desktop_in_files = gooroom-security-status-settings.desktop.in
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)

CLEANFILES = $(desktop_DATA) $(BUILT_SOURCES)
DISTCLEANFILES = Makefile.in
