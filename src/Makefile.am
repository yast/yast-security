#
# Makefile.am for y2c_sec/src
#

yncludedir = @yncludedir@/security

client_DATA =			\
	security.ycp		\
	security_auto.ycp	\
	security_write.ycp

ynclude_DATA =			\
	users.ycp		\
	dialogs.ycp		\
	wizards.ycp		\
	widgets.ycp		\
	helps.ycp		\
				\
	routines.ycp		\
	settings.ycp		\
	functions_ui.ycp	\
	io.ycp			\
	ui.ycp

module_DATA = Security.ycp

config_DATA = security.y2cc

EXTRA_DIST = $(client_DATA) $(config_DATA) $(ynclude_DATA) $(module_DATA)
