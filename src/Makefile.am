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
	settings.ycp		\
	ui_buttons.ycp		\
	ui_helps.ycp		\
	ui_widgets.ycp

include_DATA =			\
	functions.ycp		\
	functions_ui.ycp	\
	io.ycp			\
	ui.ycp

menu_DATA = menuentry_security.ycp

EXTRA_DIST = $(modules_DATA) $(menu_DATA) $(include_DATA)
