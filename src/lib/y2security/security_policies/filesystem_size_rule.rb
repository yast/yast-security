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
require "y2storage/disk_size"

module Y2Security
  module SecurityPolicies
    # Rule to check whether a file system is big enough
    class FilesystemSizeRule < Rule
      # Mount path for the file system to check
      #
      # @return [String]
      attr_reader :mount_path

      # Minimum size the file system should have
      #
      # @return [Y2Storage::DiskSize]
      attr_reader :min_size

      # Constructor
      #
      # @param id [String] See {Rule#id}
      # @param mount_path [String] See {#mount_path}
      # @param min_size [Y2Storage::DiskSize] See {#min_size}
      # @param identifiers [Array<String>] See {Rule#identifiers}
      # @param references [Array<String>] See {Rule#references}
      def initialize(id, mount_path, min_size: nil, identifiers: [], references: [])
        textdomain "security"

        min_size ||= Y2Storage::DiskSize.new(0)

        description = format(
          # TRANSLATORS: security policy rule, %s is a placeholder.
          _("The minimum size for the file system %s must be %s"), mount_path, min_size
        )

        super(id,
          identifiers: identifiers,
          references:  references,
          description: description,
          scope:       :storage)

        @mount_path = mount_path
        @min_size = min_size
      end

      # @see Rule#pass?
      def pass?(target_config)
        devicegraph = target_config.storage
        filesystem = devicegraph.blk_filesystems.find { |f| f.mount_path == mount_path }

        return false unless filesystem

        size = filesystem.blk_devices.map(&:size).reduce(:+)
        size >= min_size
      end
    end
  end
end
