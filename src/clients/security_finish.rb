# encoding: utf-8

# File:	clients/security_finish.ycp
# Package: Security configuration
# Summary: Configuration of /etc/login.defs /etc/login.defs
#          users and boot settings

require "security/clients/security_finish"
Yast::SecurityFinishClient.new.run
