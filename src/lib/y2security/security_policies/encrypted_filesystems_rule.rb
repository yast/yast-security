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
require "y2storage"

module Y2Security
  module SecurityPolicies
    # Rule to check that all file systems are encrypted (except /boot/efi)
    class EncryptedFilesystemsRule < Rule
      def initialize
        textdomain "security"

        # TRANSLATORS: Security policy rule
        description = _("All file systems must be encrypted")

        super("encrypt_partitions",
          identifiers: ["CCE-85719-3"],
          references:  ["SLES-15-010330"],
          description: description,
          scope:       :storage)
      end

      # @see Rule#pass?
      def pass?(target_config)
        devicegraph = target_config.storage
        blk_filesystems = blk_filesystems_with_missing_encryption(devicegraph)
        paths = blk_filesystems.map(&:mount_path).uniq

        paths.none?
      end

    private

      def blk_filesystems_with_missing_encryption(devicegraph)
        devicegraph.blk_filesystems.select { |f| missing_encryption?(f) }
      end

      # List of mount points that are not expected to be encrypted
      PLAIN_MOUNT_POINTS = ["/boot/efi"].freeze
      private_constant :PLAIN_MOUNT_POINTS

      def missing_encryption?(blk_filesystem)
        return false if blk_filesystem.encrypted? || blk_filesystem.mount_point.nil?

        !PLAIN_MOUNT_POINTS.include?(blk_filesystem.mount_path)
      end
    end
  end
end
