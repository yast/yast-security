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

      Yast.include self, "security/routines.rb"
      Yast.include self, "security/wizards.rb"

      @ret = nil
      @func = ""
      @param = {}

      # Check arguments
      if !Yast::WFM.Args.empty?
        @func = Yast::WFM.Args[0]
        @param = WFM.Args[1] if Yast::WFM.Args[1].is_a?(Hash)
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
        # Compat
        if Builtins.haskey(@param, "encryption")
          Ops.set(
            @param,
            "passwd_encryption",
            Ops.get_string(@param, "encryption", "des")
          )
        end
        @ret = Security.Import(Map.KeysToUpper(@param))
      # Return required packages
      when "Packages"
        @ret = {}
      # Return actual state
      when "Export"
        @ret = Security.Import(Map.KeysToUpper(Security.Export))
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
      @ret
    end
  end
end

Yast::SecurityAutoClient.new.main
