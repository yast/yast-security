# Makefile.am for security/src

yncludedir = @yncludedir@/security

YCPCFLAGS = -I .

client_DATA =			\
	security.ycp		\
	security_auto.ycp	\
	security_summary.ycp

ynclude_DATA =			\
	complex.ycp		\
	dialogs.ycp		\
	helps.ycp		\
	levels.ycp		\
	routines.ycp		\
	users.ycp		\
	widgets.ycp		\
	wizards.ycp

module_DATA = Security.ycp

config_DATA = security.y2cc

desktop_DATA = security.desktop

EXTRA_DIST = $(client_DATA) $(config_DATA) $(ynclude_DATA) $(module_DATA) $(desktop_DATA)

security:
	ln -sf . security

ycpchook = security

include $(top_srcdir)/Makefile.am.common
