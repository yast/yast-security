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
require "y2security/security_policies/policy"
require "y2security/security_policies/bootloader_password_rule"
require "y2security/security_policies/firewall_enabled_rule"
require "y2security/security_policies/missing_encryption_rule"
require "y2security/security_policies/missing_mount_point_rule"
require "y2security/security_policies/no_wireless_rule"

module Y2Security
  module SecurityPolicies
    # DISA STIG Security Policy.
    # DISA = US Defense Information Systems Agency
    # STIG = Security Technical Implementation Guides
    class DisaStigPolicy < Policy
      # @see Policy
      def initialize
        textdomain "security"

        # TRANSLATORS: This is a security policy name.
        #   "Defense Information Systems Agency" is from the USA, https://disa.mil/
        #   STIG = Security Technical Implementation Guides
        super(:disa_stig, _("Defense Information Systems Agency STIG"))
      end

      def rules
        @rules ||= [
          MissingMountPointRule.new("SLES-15-040200", "/home"),
          MissingMountPointRule.new("SLES-15-040210", "/var"),
          MissingMountPointRule.new("SLES-15-030810", "/var/log/audit"),
          MissingEncryptionRule.new,
          NoWirelessRule.new,
          FirewallEnabledRule.new,
          BootloaderPasswordRule.new
        ]
      end
    end
  end
end
