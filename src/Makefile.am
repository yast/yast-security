# Sources for security

module_DATA = \
  modules/Security.rb

client_DATA = \
  clients/security_summary.rb \
  clients/security.rb \
  clients/security_auto.rb

yncludedir = @yncludedir@/security
ynclude_DATA = \
  include/security/levels.rb \
  include/security/widgets.rb \
  include/security/wizards.rb \
  include/security/dialogs.rb \
  include/security/complex.rb \
  include/security/users.rb \
  include/security/routines.rb \
  include/security/helps.rb

schemafilesdir = $(schemadir)/autoyast/rnc
schemafiles_DATA = \
  autoyast-rnc/security.rnc

scrconf_DATA = \
  scrconf/cfg_locate.scr \
  scrconf/etc_polkit-default-privs_local.scr \
  scrconf/kde4_kdmrc.scr

ydatadir = @ydatadir@/security
ydata_DATA = \
  data/security/services.yml

desktop_DATA = \
  desktop/security.desktop

EXTRA_DIST = $(module_DATA) $(client_DATA) $(ynclude_DATA) $(schemafiles_DATA) $(scrconf_DATA) $(ydata_DATA) $(desktop_DATA)

include $(top_srcdir)/Makefile.am.common
