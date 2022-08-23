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

require "bootloader/bootloader_factory"

module Y2Security
  module SecurityPolicies
    module Scopes
      # Scope for bootloader checks
      class Bootloader
        # Bootloader to use with this scope
        #
        # @return [Bootloader::BootloaderFactory]
        attr_reader :bootloader

        # Constructor
        #
        # @param bootloader [Bootloader::BootloaderFactory] Bootloader to use with this scope. If no
        #   bootloader is given, then the currently configured bootloader is used.
        def initialize(bootloader: nil)
          @bootloader = bootloader || default_bootloader
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
end
