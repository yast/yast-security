#
# Makefile.am for y2c_sec/src
#

menudir = $(YAST2DIR)/menuentries
modulesdir = $(YAST2DIR)/clients
includedir = $(YAST2DIR)/include/security

modules_DATA =			\
	buttons.ycp		\
	security.ycp		\
	security_helps.ycp	\
	security_settings.ycp	\
	security_widgets.ycp    \
	security_write.ycp

include_DATA =			\
	general.ycp		\
	general_ui.ycp		\
	security_io.ycp		\
	security_ui.ycp

menu_DATA = menuentry_security.ycp

EXTRA_DIST = $(modules_DATA) $(menu_DATA) $(include_DATA)
