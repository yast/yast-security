# Copyright (c) [2021] SUSE LLC
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

require "installation/autoinst_profile/section_with_attributes"

module Y2Security
  module AutoinstProfile
    # This class represents an AutoYaST <selinux> section under <lsm>
    #
    # <selinux>
    #   <mode>permissive</mode>
    #   <configurable config:type="boolean">true</configurable>
    #   <selectable config:type="boolean">true</selectable>
    #   <patterns>selinux</patterns>
    # </selinux>
    class SelinuxSection < ::Installation::AutoinstProfile::SectionWithAttributes
      def self.attributes
        [
          { name: :mode },
          { name: :configurable },
          { name: :selectable },
          { name: :patterns }
        ]
      end

      define_attr_accessors

      # @!attribute mode
      #   @return [String]
      # @!attribute configurable
      #   @return [Boolean]
      # @!attribute selectable
      #   @return [Boolean]
      # @!attribute patterns
      #   @return Array<String>
      def initialize(*_args)
        super

        @patterns = []
      end
    end
  end
end
