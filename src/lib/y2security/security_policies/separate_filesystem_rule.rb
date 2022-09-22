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

module Y2Security
  module SecurityPolicies
    # Rule to check whether there is a separate file system for a given path
    class SeparateFilesystemRule < Rule
      # Mount path for the file system to check
      #
      # @return [String]
      attr_reader :mount_path

      # @param name [String] Rule name
      # @param id [String] Rule ID
      # @param mount_path [String] Mount path for the file system to check
      def initialize(name, id, mount_path)
        textdomain "security"

        @mount_path = mount_path
        # TRANSLATORS: security policy rule, %s is a placeholder.
        description = format(_("There must be a separate file system for %s"), mount_path)

        super(name, id: id, description: description, scope: :storage)
      end

      # @see Rule#pass?
      def pass?(target_config)
        devicegraph = target_config.storage
        devicegraph.blk_filesystems.any? { |f| f.mount_path == mount_path }
      end
    end
  end
end
