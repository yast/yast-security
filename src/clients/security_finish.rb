# encoding: utf-8

# File:	clients/security_finish.rb
# Package: Security configuration
# Summary: Configuration of /etc/login.defs /etc/sysctl.conf
#          users and boot settings

require "security/clients/security_finish"
Yast::SecurityFinishClient.new.run
