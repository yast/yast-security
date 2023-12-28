# encoding: utf-8

# ------------------------------------------------------------------------------
# Copyright (c) 2006-2012 Novell, Inc. All Rights Reserved.
#
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of version 2 of the GNU General Public License as published by the
# Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, contact Novell, Inc.
#
# To contact Novell about this file by physical or electronic mail, you may find
# current contact information at www.novell.com.
# ------------------------------------------------------------------------------

# File:	clients/security.ycp
# Package:	Security configuration
# Summary:	Main file
# Authors:	Michal Svec <msvec@suse.cz>
#
# $Id$
#
# This is a main file of the module. There is in the file
# only some calls to the basic functions. The settings are
# initialized, main dialog is called and then settings are
# saved.
module Yast
  class SecurityClient < Client
    def main
      Yast.import "UI"

      #**
      # <h3> Security configuration

      textdomain "security"

      # The main ()
      Builtins.y2milestone("----------------------------------------")
      Builtins.y2milestone("Security module started")

      Yast.import "CommandLine"
      Yast.import "Report"
      Yast.import "Security"

      Yast.include self, "security/wizards.rb"

      # the command line description map
      @cmdline = {
        "id"         => "security",
        # translators: command line help text for Security module
        "help"       => _(
          "Security configuration module"
        ),
        "guihandler" => fun_ref(method(:SecuritySequence), "any ()"),
        "initialize" => fun_ref(Security.method(:Read), "boolean ()"),
        "finish"     => fun_ref(Security.method(:Write), "boolean ()"),
        "actions"    => {
          "summary" => {
            "handler" => fun_ref(
              method(:SecuritySummaryHandler),
              "boolean (map)"
            ),
            # command line help text for 'summary' action
            "help"    => _(
              "View summary of current configuration"
            )
          },
          "level"   => {
            "handler" => fun_ref(method(:SecurityLevelHandler), "boolean (map)"),
            # command line help text for 'level' action
            "help"    => _(
              "Set the security level"
            )
          },
          "set"     => {
            "handler" => fun_ref(method(:SecuritySetHandler), "boolean (map)"),
            # command line help text for 'set' action
            "help"    => _(
              "Set the value of the specific option"
            )
          }
        },
        "options"    => {
          "workstation" => {
            # command line help text for 'level workstation' option
            "help" => _(
              "Workstation security level"
            )
          },
          "roaming"     => {
            # command line help text for 'level roaming' option
            "help" => _(
              "Roaming Device (e.g. laptop or tablet) security level"
            )
          },
          "server"      => {
            # command line help text for 'level server' option
            "help" => _(
              "Network Server security level"
            )
          },
          "passwd"      => {
            # command line help text for 'set passwd' option
            "help"     => _(
              "Password encryption method"
            ),
            "type"     => "enum",
            "typespec" => ["des", "md5", "sha256", "sha512"]
          },
          "crack"       => {
            # command line help text for 'set crack' option
            "help"     => _(
              "Check new passwords"
            ),
            "type"     => "enum",
            "typespec" => ["yes", "no"]
          },
          "permissions" => {
            # command line help text for 'set permissions' option
            "help"     => _(
              "Set file permissions to desired type"
            ),
            "type"     => "enum",
            "typespec" => ["easy", "secure", "paranoid"]
          },
          "remember"    => {
            # command line help text for 'set remember' option
            "help" => _(
              "Set the number of remembered user passwords"
            ),
            "type" => "string"
          }
        },
        "mappings"   => {
          "summary" => [],
          "level"   => ["workstation", "roaming", "server"],
          #FIXME: 1,2,3 aliases
          "set"     => [
            "passwd",
            "crack",
            "permissions",
            "remember"
          ]
        }
      }

      @ret = CommandLine.Run(@cmdline)
      Builtins.y2debug("ret == %1", @ret)

      # Finish
      Builtins.y2milestone("Security module finished")
      Builtins.y2milestone("----------------------------------------")
      deep_copy(@ret) 

      # EOF
    end

    # --------------------------------------------------------------------------
    # --------------------------------- cmd-line handlers

    # Print security summary
    # @return [Boolean] false
    def SecuritySummaryHandler(options)
      options = deep_copy(options)
      sum = Security.Summary
      CommandLine.Print(Ops.get_string(sum, 0, ""))
      false # do not call Write...
    end

    # Set security level
    # @return [Boolean] successfully modified?
    def SecurityLevelHandler(options)
      options = deep_copy(options)
      current = :custom
      Builtins.maplist(@Levels) do |key, level|
        current = key if level == Security.Settings
      end
      lvl = ""
      if options.key?("workstation")
        lvl = "Level1"
      elsif options.key?("roaming")
        lvl = "Level2"
      elsif options.key?("server")
        lvl = "Level3"
      end

      if current != lvl
        Security.Settings = Ops.get(@Levels, lvl, {})
        Security.modified = true
        return true
      end
      false
    end

    # Set value of specific security option
    # @return [Boolean] false
    def SecuritySetHandler(options)
      options = deep_copy(options)
      if Builtins.haskey(options, "passwd") &&
          Ops.get_string(options, "passwd", "") !=
            Ops.get(Security.Settings, "PASSWD_ENCRYPTION", "")
        Ops.set(
          Security.Settings,
          "PASSWD_ENCRYPTION",
          Ops.get_string(options, "passwd", Security.default_encrypt_method)
        )
        Security.modified = true
      end
      if Builtins.haskey(options, "crack") &&
          Ops.get_string(options, "crack", "") !=
            Ops.get(Security.Settings, "PASSWD_USE_PWQUALITY", "")
        Ops.set(
          Security.Settings,
          "PASSWD_USE_PWQUALITY",
          Ops.get_string(options, "crack", "yes")
        )
        Security.modified = true
      end
      if Builtins.haskey(options, "permissions") &&
          !Builtins.issubstring(
            Ops.get(Security.Settings, "PERMISSION_SECURITY", ""),
            Ops.get_string(options, "permissions", "")
          )
        Ops.set(
          Security.Settings,
          "PERMISSION_SECURITY",
          Ops.add(Ops.get_string(options, "permissions", ""), " local")
        )
        Security.modified = true
      end

      if Builtins.haskey(options, "remember") &&
          Ops.get(Security.Settings, "PASSWD_REMEMBER_HISTORY", "0") !=
            Ops.get_string(options, "remember", "0")
        to_remember = Builtins.tointeger(
          Ops.get_string(options, "remember", "0")
        )
        if to_remember == nil || Ops.less_than(to_remember, 0) ||
            Ops.greater_than(to_remember, 400)
          # error message
          Report.Error(
            _("The number of passwords to remember must be between 0 an 400.")
          )
          return false
        end
        Ops.set(
          Security.Settings,
          "PASSWD_REMEMBER_HISTORY",
          Ops.get_string(options, "remember", "0")
        )
        Security.modified = true
      end
      Security.modified
    end
  end
end

Yast::SecurityClient.new.main
