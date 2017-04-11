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
  # module to hold information from CtrlAltDelConfig
  module CtrlAltDelConfig
    include Yast::Logger
    Yast.import "SCR"
    Yast.import "Arch"
    Yast.import "Package"
    Yast.import "FileUtils"

    SYSTEMD_FILE = "/etc/systemd/system/ctrl-alt-del.target".freeze

    class << self
      def systemd?
        Yast::Package.Installed("systemd")
      end

      def inittab?
        Yast::FileUtils.Exists("/etc/inittab")
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
        return current_inittab if inittab?
        nil
      end

      def current_systemd
        if !Yast::FileUtils.Exists(SYSTEMD_FILE)
          ret = nil
        else
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
        end
        ret
      end

      def current_inittab
        ca = Yast::SCR.Read(Yast::Path.new(".etc.inittab.ca"))
        ret =
          case ca
          when /\/bin\/true/, /\/bin\/false/
            "ignore"
          when /reboot/, / -r/
            "reboot"
          when /halt/, / -h/
            "halt"
          when nil
            log.error("No ca entry")
            nil
          else
            log.error "Unknown ca status: #{ca}"
            "ignore"
          end
        ret
      end
    end
  end
end
