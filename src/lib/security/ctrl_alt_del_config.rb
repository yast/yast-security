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
  module CtrlAltDelConfig
    include Yast::Logger
    Yast.import "SCR"
    Yast.import "Arch"
    Yast.import "Package"
    Yast.import "FileUtils"

    SYSTEMD_FILE = "/etc/systemd/system/ctrl-alt-del.target".freeze

    class << self
      def systemd?
        Yast::Package.Installed("systemd", target: :system)
      end

      def default
        Yast::Arch.s390 ? "halt" : "reboot"
      end

      def options
        options = ["ignore", "reboot", "halt"]

        options.delete("reboot") if Yast::Arch.s390

        options
      end

      def current
        return current_systemd if systemd?

        nil
      end

      def current_systemd
        if Yast::FileUtils.Exists(SYSTEMD_FILE)
          link = Yast::SCR.Read(Yast::Path.new(".target.symlink"), SYSTEMD_FILE).to_s
          ret =
            case link
            when "/usr/lib/systemd/system/poweroff.target"
              "halt"
            when "/usr/lib/systemd/system/reboot.target"
              "reboot"
            when "/usr/lib/systemd/system/ctrl-alt-del.target"
              default
            else
              log.error "Not known link #{link}"
              "ignore"
            end
        else
          ret = nil
        end
        ret
      end
    end
  end
end
