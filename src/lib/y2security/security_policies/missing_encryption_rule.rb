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
require "y2security/security_policies/issue"
require "y2storage"

module Y2Security
  module SecurityPolicies
    # Rule to check that all file systems are encrypted (except /boot/efi) (SLES-15-010330).
    class MissingEncryptionRule < Rule
      def initialize
        super("SLES-15-010330", :storage)
      end

      # @param devicegraph [Y2Storage::Devicegraph] Devicegraph to check
      # @see Rule#validate
      def validate(devicegraph = nil)
        devicegraph ||= Y2Storage::StorageManager.instance.staging
        blk_filesystems = blk_filesystems_with_missing_encryption(devicegraph)
        paths = blk_filesystems.map(&:mount_path).uniq.sort

        return nil if paths.none?

        Issue.new(
          format(_("The following file systems are not encrypted: %s"), paths.join(", ")),
          scope: scope
        )
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
