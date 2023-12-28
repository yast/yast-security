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

# File:	clients/security_auto.ycp
# Package:	Security configuration
# Summary:	Client for autoinstallation
# Authors:	Michal Svec <msvec@suse.cz>
#
# $Id$
#
# This is a client for autoinstallation. It takes its arguments,
# goes through the configuration and return the setting.
# Does not do any changes to the configuration.

require "y2security/lsm"

# @param function to execute
# @param map/list of security settings
# @return [Hash] edited settings, Summary or boolean on success depending on called function
# @example map mm = $[ "FAIL_DELAY" : "77" ];
# @example map ret = WFM::CallFunction ("security_auto", [ "Summary", mm ]);
module Yast
  class SecurityAutoClient < Client
    def main
      Yast.import "UI"

      textdomain "security"

      Builtins.y2milestone("----------------------------------------")
      Builtins.y2milestone("Security auto started")

      Yast.import "Map"
      Yast.import "Security"
      Yast.import "AutoInstall"

      Yast.include self, "security/routines.rb"
      Yast.include self, "security/wizards.rb"

      @ret = nil
      @func = ""
      @param = {}

      # Check arguments
      if Ops.greater_than(Builtins.size(WFM.Args), 0) &&
          Ops.is_string?(WFM.Args(0))
        @func = Convert.to_string(WFM.Args(0))
        if Ops.greater_than(Builtins.size(WFM.Args), 1) &&
            Ops.is_map?(WFM.Args(1))
          @param = Convert.to_map(WFM.Args(1))
        end
      end
      Builtins.y2debug("func=%1", @func)
      Builtins.y2debug("param=%1", @param)

      # Create a  summary
      case @func
      when "Summary"
        @summary = Security.Summary
        @ret = Ops.get_string(@summary, 0, "")
      # Reset configuration
      when "Reset"
        Security.Import({})
        @ret = {}
      # Change configuration (run AutoSequence)
      when "Change"
        @ret = SecurityAutoSequence()
      # Import Data
      when "Import"

        # Checking value semantic
        if @param.key?("selinux_mode")
          selinux_values = Y2Security::LSM::Selinux.new.modes.map { |m| m.id.to_s }
          if !selinux_values.include?(@param["selinux_mode"])
            Yast::AutoInstall.issues_list.add(
              :invalid_value,
              "security",
              "selinux_mode",
              @param["selinux_mode"],
              _("Wrong SELinux mode. Possible values: ") +
              selinux_values.join(", "),
              :warn
            )
          end
        end

        # Compat
        if Builtins.haskey(@param, "encryption")
          Ops.set(
            @param,
            "passwd_encryption",
            Ops.get_string(@param, "encryption", Security.default_encrypt_method)
          )
        end
        @ret = Security.Import(
          Map.KeysToUpper(
            Convert.convert(@param, :from => "map", :to => "map <string, any>")
          )
        )
      # Return required packages
      when "Packages"
        @ret = {}
      # Return actual state
      when "Export"
        @ret = Map.KeysToLower(
          Convert.convert(
            Security.Export,
            :from => "map",
            :to   => "map <string, any>"
          )
        )
      # Read current state
      when "Read"
        Yast.import "Progress"
        Progress.off
        @ret = Security.Read
        Progress.on
      # Write givven settings
      when "Write"
        Yast.import "Progress"
        Security.write_only = true
        Progress.off
        @ret = Security.Write
        Progress.on
      when "SetModified"
        @ret = Security.SetModified
      when "GetModified"
        @ret = Security.GetModified
      else
        Builtins.y2error("Unknown function: %1", @func)
        @ret = false
      end

      Builtins.y2debug("ret=%1", @ret)
      Builtins.y2milestone("Security auto finished")
      Builtins.y2milestone("----------------------------------------")

      deep_copy(@ret)

      # EOF
    end
  end
end

Yast::SecurityAutoClient.new.main
