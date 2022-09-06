# Copyright (c) [2022] SUSE LLC
#
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of version 2 of the GNU General Public License as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, contact SUSE LLC.
#
# To contact SUSE LLC about this file by physical or electronic mail, you may
# find current contact information at www.suse.com.

require "yast"
require "y2security/security_policies/rule"
require "y2security/security_policies/issue"
require "bootloader/bootloader_factory"

module Y2Security
  module SecurityPolicies
    #  Run to check whether grub2 is password-protected and menu editing is restricted
    #  (SLES-15-010200).
    class BootloaderPasswordRule < Rule
      def initialize
        super("SLES-15-010200", :bootloader)
      end

      # @param bootloader [Bootloader::BootloaderFactory] Bootloader configuration
      # @see Rule#validate
      def validate(bootloader = nil)
        bootloader ||= default_bootloader
        return nil unless bootloader.is_a?(Bootloader::Grub2Base)

        password = bootloader.password
        if !password&.used? || password&.unrestricted
          Issue.new(_("Bootloader must be protected by password and menu editing must be restricted"), scope: scope)
        end
      end

    private

      # Default bootloader to use
      #
      # @return [Bootloader::BootloaderFactory]
      def default_bootloader
        ::Bootloader::BootloaderFactory.current
      end
    end
  end
end
