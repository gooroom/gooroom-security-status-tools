gsettings_SCHEMAS = apps.gooroom-security-status-view.gschema.xml
@GSETTINGS_RULES@

gooroom_security_status_view_CPPFLAGS = \
	-I$(top_srcdir)/common/	\
	-DLOCALEDIR=\"$(localedir)\"	\
	-DGOOROOM_UPDATE_CHECKER=\"$(pkglibexecdir)/gooroom-update-checker\" \
	-DGOOROOM_IPTABLES_WRAPPER=\"$(pkglibexecdir)/gooroom-iptables-wrapper\" \
	-DGOOROOM_IP6TABLES_WRAPPER=\"$(pkglibexecdir)/gooroom-ip6tables-wrapper\" \
	-DGOOROOM_PRODUCT_UUID_HELPER=\"$(pkglibexecdir)/gooroom-product-uuid-helper\" \
	-DGOOROOM_WHICH_GRAC_RULE=\"/usr/lib/gooroom-resource-access-control/which-grac-rule.py\" \
	-DGOOROOM_SECURITY_STATUS_VULNERABLE_HELPER=\"$(pkglibexecdir)/gooroom-security-status-vulnerable-helper\" \
	$(AM_CPPFLAGS)


bin_PROGRAMS = gooroom-security-status-view

BUILT_SOURCES = \
	sysinfo-resources.c \
	sysinfo-resources.h

gooroom_security_status_view_SOURCES = \
	$(BUILT_SOURCES)	\
	main.c				\
	sysinfo-window.h	\
	sysinfo-window.c	\
	rpd-dialog.h		\
	rpd-dialog.c		\
	calendar-popover.h	\
	calendar-popover.c	\
	logfilter-popover.h	\
	logfilter-popover.c

gooroom_security_status_view_CFLAGS =  \
	$(GLIB_CFLAGS)      \
	$(GTK3_CFLAGS)       \
	$(JSON_C_CFLAGS)    \
	$(DBUS_CFLAGS)      \
	$(DBUS_GLIB_CFLAGS) \
	$(AM_CFLAGS)

gooroom_security_status_view_LDFLAGS = \
	$(AM_LDFLAGS)

gooroom_security_status_view_LDADD =   \
	$(GLIB_LIBS)	\
	$(GTK3_LIBS)	\
	$(JSON_C_LIBS)	\
	$(DBUS_LIBS)	\
	$(DBUS_GLIB_LIBS)	\
	$(top_builddir)/common/libcommon.la

resource_files = $(shell glib-compile-resources --sourcedir=$(srcdir) --generate-dependencies $(srcdir)/gresource.xml)
sysinfo-resources.c: gresource.xml $(resource_files)
	$(AM_V_GEN) glib-compile-resources --target=$@ --sourcedir=$(srcdir) --generate-source --c-name sysinfo $<
sysinfo-resources.h: gresource.xml $(resource_files)
	$(AM_V_GEN) glib-compile-resources --target=$@ --sourcedir=$(srcdir) --generate-header --c-name sysinfo $<

@INTLTOOL_DESKTOP_RULE@
desktopdir = $(datadir)/applications
desktop_in_files = gooroom-security-status-view.desktop.in
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)

CLEANFILES = $(desktop_DATA) $(BUILT_SOURCES)
DISTCLEANFILES = Makefile.in
