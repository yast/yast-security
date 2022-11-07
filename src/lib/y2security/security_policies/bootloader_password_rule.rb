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

require "y2security/security_policies/rule"
require "y2storage/arch"

module Y2Security
  module SecurityPolicies
    #  Run to check whether grub2 is password-protected and menu editing is restricted
    class BootloaderPasswordRule < Rule
      def initialize
        textdomain "security"

        # TRANSLATORS: security policy rule
        description = _("Boot loader must be protected by password and menu editing must be " \
          "restricted")

        # DISA STIG defines a rule for UEFI (SLES-15-010200) and another rule for non-UEFI
        # (SLES-15-010190). The condition to check both rules in YaST is exactly the same, so let's
        # simply adapt the rule info according to the system type.
        if Y2Storage::Arch.new.efiboot?
          super("grub2_uefi_password",
            identifiers: ["CCE-83275-8"],
            references:  ["SLES-15-010200"],
            description: description,
            scope:       :bootloader)
        else
          super("grub2_password",
            identifiers: ["CCE-83274-1"],
            references:  ["SLES-15-010190"],
            description: description,
            scope:       :bootloader)
        end
      end

      # @see Rule#pass?
      def pass?(target_config)
        bootloader = target_config.bootloader

        return true unless bootloader.is_a?(Bootloader::Grub2Base)

        password = bootloader.password
        return false unless password

        password.used? && !password.unrestricted
      end
    end
  end
end
