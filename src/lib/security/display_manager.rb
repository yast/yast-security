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
require 'security/display_manager/base'
require 'security/display_manager/kdm'
require 'security/display_manager/gdm'


module Security
  module DisplayManager
    Yast.import "SCR"

    CONFIG_PATH = ".sysconfig.displaymanager.DISPLAYMANAGER"

    DEFAULT = GDM

    DISPLAY_MANAGERS = {
      "kdm" => KDM
    }

    def self.current
      @name = Yast::SCR.Read(Yast::Path.new(CONFIG_PATH))

      (DISPLAY_MANAGERS[@name] || DEFAULT).new(@name)
    end
  end
end
