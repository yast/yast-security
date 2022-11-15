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
require "y2security/security_policies/separate_mount_point_rule"
require "y2security/security_policies/separate_filesystem_rule"
require "y2security/security_policies/filesystem_size_rule"
require "y2security/security_policies/encrypted_filesystems_rule"
require "y2security/security_policies/bootloader_password_rule"
require "y2security/security_policies/firewall_enabled_rule"
require "y2security/security_policies/no_wireless_rule"
require "y2storage/disk_size"

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
        name = _("Defense Information Systems Agency STIG")

        super(:stig, name)
      end

      def rules
        @rules ||= [
          SeparateMountPointRule.new("partition_for_home", "/home",
            identifiers: ["CCE-85639-3"],
            references:  ["SLES-15-040200"]),
          SeparateMountPointRule.new("partition_for_var", "/var",
            identifiers: ["CCE-85640-1"],
            references:  ["SLES-15-040210"]),
          SeparateFilesystemRule.new("partition_for_var_log_audit", "/var/log/audit",
            identifiers: ["CCE-85618-7"],
            references:  ["SLES-15-030810"]),
          FilesystemSizeRule.new("auditd_audispd_configure_sufficiently_large_partition",
            "/var/log/audit",
            min_size:    Y2Storage::DiskSize.MiB(100),
            identifiers: ["CCE-85697-1"],
            references:  ["SLES-15-030660"]),
          EncryptedFilesystemsRule.new,
          BootloaderPasswordRule.new,
          FirewallEnabledRule.new,
          NoWirelessRule.new
        ]
      end
    end
  end
end
