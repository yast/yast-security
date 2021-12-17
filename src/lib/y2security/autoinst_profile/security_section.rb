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
require "y2security/autoinst_profile/lsm_section"

module Y2Security
  module AutoinstProfile
    # This class represents an AutoYaST <security> section although by now it only handles
    # LSM related attributes
    #
    # <security>
    #   <selinux_mode></selinux_mode> # Deprecated
    #   <lsm>
    #     <apparmor>
    #       <selectable config:type="boolean">false</selectable>
    #     </apparmor>
    #     <selinux>
    #       <mode>permissive</mode>
    #       <configurable config:type="boolean">true</configurable>
    #       <patterns>selinux</patterns>
    #     </selinux>
    #   </lsm>
    # </security>
    class SecuritySection < ::Installation::AutoinstProfile::SectionWithAttributes
      def self.attributes
        [
          { name: :selinux_mode }, # Deprecated
          { name: :lsm }
        ]
      end

      define_attr_accessors

      # @!attribute selinux_mode
      #   @return [String] SELinux mode to be used
      #   @deprecated
      #
      # @!attribute lsm
      #   @return [LSMSection]

      def init_from_hashes(hash)
        super

        # backward compatible with option 'selinux_mode'
        hash["lsm"] ||= { "select" => "selinux", "selinux" => { "mode" => @selinux_mode } } if @selinux_mode

        @lsm = LSMSection.new_from_hashes(hash["lsm"], self) if hash["lsm"]

        nil
      end
    end
  end
end
