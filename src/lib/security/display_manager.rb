# ------------------------------------------------------------------------------
# Copyright (c) 2016 SUSE LLC, All Rights Reserved.
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

    CONFIG_PATH = ".sysconfig.displaymanager.DISPLAYMANAGER".freeze

    SYSCONFIG_COMMON_LOCATIONS = [
      "DISPLAYMANAGER_REMOTE_ACCESS",
      "DISPLAYMANAGER_ROOT_LOGIN_REMOTE",
      "DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN"
    ].freeze

    private_class_method :new
    attr_reader :name

    def self.current
      configured_dm = Yast::SCR.Read(Yast::Path.new(CONFIG_PATH)).to_s
      configured_dm.empty? ? nil : new(configured_dm)
    end

    def initialize(name)
      @name = name
    end

    def kdm?
      @name == "kdm"
    end

    def default_settings
      kdm? ? { "AllowShutdown" => "All" } : {}
    end

    def shutdown_var_name
      @shutdown_var_name ||= kdm? ? "AllowShutdown" : ""
    end

    def shutdown_default_value
      @shutdown_default_value ||= kdm? ? "All" : ""
    end

    def shutdown_options
      @shutdown_options ||= kdm? ? ["Root", "All", "None"] : []
    end

    def default_locations
      locations = { ".sysconfig.displaymanager" => SYSCONFIG_COMMON_LOCATIONS }
      locations[".kde4.kdmrc"] = ["AllowShutdown"] if kdm?

      locations
    end
  end
end
