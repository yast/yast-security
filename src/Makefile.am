#
# Makefile.am for y2c_sec/src
#

menudir = $(YAST2DIR)/menuentries
modulesdir = $(YAST2DIR)/clients
clientsdir = $(YAST2DIR)/clients
#clientsdir = $(YAST2DIR)/clients/security
includedir = $(YAST2DIR)/include/security

modules_DATA =			\
	security.ycp		\
	security_write.ycp

clients_DATA =			\
	ui_buttons.ycp		\
	ui_helps.ycp		\
	ui_widgets.ycp

include_DATA =			\
	routines.ycp		\
	settings.ycp		\
	functions_ui.ycp	\
	io.ycp			\
	ui.ycp

menu_DATA = menuentry_security.ycp

EXTRA_DIST = $(modules_DATA) $(clients_DATA) $(menu_DATA) $(include_DATA)
