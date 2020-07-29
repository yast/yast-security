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

# File:	include/security/levels.ycp
# Module:	Security configuration
# Summary:	Security settings definitions
# Authors:	Michal Svec <msvec@suse.cz>
#
# $Id$
#
# This file contains definitions of all security settings.
# They are in one huge list.
#
# <pre>
# $[
#   "name" : &lt;string Level>
#   "settings" : $[
#     &lt;string ID> : &lt;string Value>,
#     ...
#   ]
# ]
# </pre>

require "yaml"

# @return [Array] all security settings
module Yast
  module SecurityLevelsInclude
    def initialize_security_levels(include_target)
      textdomain "security"
      Yast.import "Directory"

      # Level names definitions
      @LevelsNames = {
        # level name
        "Level1" => _("Workstation"),
        # level name
        "Level2" => _("Roaming Device"),
        # level name
        "Level3" => _("Network Server")
      }

      @LevelsLabels = {
        # RadioButton label
        "Level1" => _("&Workstation"),
        # RadioButton label
        "Level2" => _("&Roaming Device"),
        # RadioButton label
        "Level3" => _("Network &Server")
      }

      # Levels definitions
      @Levels = @LevelsNames.keys.each_with_object({}) do |level, levels|
        lfile = Directory.find_data_file("security/#{level.downcase}.yml")
        raise(Errno::ENOENT, "#{level.downcase}.yml file not found") unless lfile

        levels[level] = YAML.load_file(lfile)
      end

      # EOF
    end
  end
end
