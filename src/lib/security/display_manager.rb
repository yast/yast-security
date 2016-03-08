# encoding: utf-8

# ------------------------------------------------------------------------------
# Copyright (c) 2015 SUSE LLC, All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, contact SUSE LLC.
#
# To contact SUSE about this file by physical or electronic mail, you may find
# current contact information at www.suse.com.
# ------------------------------------------------------------------------------
#

require "yast"

module Security
  class DisplayManager
    Yast.import "SCR"

    CONFIG_PATH = ".sysconfig.displaymanager.DISPLAYMANAGER"

    SYSCONFIG_COMMON_LOCATIONS = [
      "DISPLAYMANAGER_REMOTE_ACCESS",
      "DISPLAYMANAGER_ROOT_LOGIN_REMOTE",
      "DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN"
    ]

    attr_reader :name

    def self.current
      @display_manager = DisplayManager.new
    end

    def initialize
      @name = Yast::SCR.Read(Yast::Path.new(CONFIG_PATH)).to_s
    end

    def kdm?
      @name == "kdm"
    end

    def default_settings
      { shutdown_key => default_value }
    end

    def shutdown_key
      @shutdown_key ||= kdm? ? "AllowShutdown" : "DISPLAYMANAGER_SHUTDOWN"
    end

    def default_value
      @default_value ||= kdm? ? "All" : "all"
    end

    def options
      @options ||= kdm? ? ["Root", "All", "None"] : ["root", "all", "none"]
    end

    def default_locations
      sysconfig_locations = SYSCONFIG_COMMON_LOCATIONS
      sysconfig_locations << shutdown_key if !kdm?

      locations = { ".sysconfig.displaymanager" => sysconfig_locations }

      locations[".kde4.kdmrc"] = ["AllowShutdown"] if kdm?

      locations
    end
  end
end
