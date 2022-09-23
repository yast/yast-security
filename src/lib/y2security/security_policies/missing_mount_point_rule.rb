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
    # Rule to check whether there is a separate mount point for a given path
    class MissingMountPointRule < Rule
      # @return [String] Mount point to check
      attr_reader :mount_point

      # @param name [String] Rule name
      # @param id [String] Rule ID
      # @param mount_point [String] Mount point to check
      def initialize(name, id, mount_point)
        textdomain "security"

        @mount_point = mount_point
        # TRANSLATORS: security policy rule
        description = format(_("There must be a separate mount point for %s"), mount_point)

        super(name, id: id, description: description, scope: :storage)
      end

      # @see Rule#pass?
      def pass?(target_config)
        devicegraph = target_config.storage
        paths = devicegraph.mount_points.map(&:path)

        paths.include?(mount_point)
      end
    end
  end
end
