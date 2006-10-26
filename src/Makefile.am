# Makefile.am for security/src

yncludedir = @yncludedir@/security

rncdir =  $(schemadir)/autoyast/rnc

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

desktop_DATA = security.desktop

rnc_DATA = security.rnc

EXTRA_DIST = $(client_DATA) $(ynclude_DATA) $(module_DATA) $(desktop_DATA) $(rnc_DATA)

security:
	ln -sf . security

ycpchook = security

include $(top_srcdir)/Makefile.am.common
