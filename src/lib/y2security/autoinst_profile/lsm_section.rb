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
require "y2security/autoinst_profile/selinux_section"
require "y2security/autoinst_profile/apparmor_section"

module Y2Security
  module AutoinstProfile
    # This class represents an AutoYaST <lsm> section
    #
    # <lsm>
    #   <select>selinux</select>
    #   <apparmor>
    #     <selectable config:type="boolean">false</selectable>
    #   </apparmor>
    #   <none>
    #     <selectable config:type="boolean">false</selectable>
    #   </none>
    #   <selinux>
    #     <mode>permissive</mode>
    #     <configurable config:type="boolean">true</configurable>
    #     <patterns>selinux</patterns>
    #   </selinux>
    # </lsm>
    class LSMSection < ::Installation::AutoinstProfile::SectionWithAttributes
      def self.attributes
        [
          { name: :select },
          { name: :configurable },
          { name: :selinux },
          { name: :apparmor },
          { name: :none }
        ]
      end

      define_attr_accessors

      # @!attribute select
      #   @return [String]
      # @!attribute configurable
      #   @return [Boolean]
      # @!attribute selinux
      #   @return [SelinuxSection]
      # @!attribute apparmor
      #   @return [ApparmorSection]

      def init_from_hashes(hash)
        super

        @selinux = SelinuxSection.new_from_hashes(hash["selinux"], self) if hash["selinux"]
        @apparmor = ApparmorSection.new_from_hashes(hash["apparmor"], self) if hash["apparmor"]
        @none = ApparmorSection.new_from_hashes(hash["none"], self) if hash["none"]

        nil
      end
    end
  end
end
