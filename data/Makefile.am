gooroom_security_status_toolsdir = $(pkglibexecdir)
gooroom_security_status_tools_SCRIPTS = \
	gooroom-client-server-register-wrapper \
	gooroom-logparser-seektime-helper	\
	gooroom-security-logparser-wrapper	\
	gooroom-update-checker	\
	gooroom-iptables-wrapper \
	gooroom-ip6tables-wrapper \
	gooroom-product-uuid-helper \
	gooroom-security-status-vulnerable-helper

kr.gooroom.security.status.tools.policy.in: kr.gooroom.security.status.tools.policy.in.in Makefile
	$(AM_V_GEN) sed -e "s|\@pkglibexecdir\@|$(pkglibexecdir)|" $< >$@

@INTLTOOL_POLICY_RULE@
polkitdir       = $(datadir)/polkit-1/actions
polkit_in_files = kr.gooroom.security.status.tools.policy.in
polkit_DATA     = $(polkit_in_files:.policy.in=.policy)

CLEANFILES = \
	kr.gooroom.security.status.tools.policy \
	kr.gooroom.security.status.tools.policy.in

DISTCLEANFILES = Makefile.in
