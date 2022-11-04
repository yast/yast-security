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
require "y2security/autoinst_profile/security_policy_section"

module Y2Security
  module AutoinstProfile
    # This class represents an AutoYaST <security> section although by now it only handles
    # LSM related attributes
    #
    # <security>
    #   <selinux_mode>enforcing</selinux_mode>
    #   <lsm_select>selinux</lsm_select>
    #   <security_policy>
    #     <policy>stig</policy>
    #     <action>remediate</action>
    #   </security_policy>
    # </security>
    class SecuritySection < ::Installation::AutoinstProfile::SectionWithAttributes
      def self.attributes
        [
          { name: :selinux_mode },
          { name: :lsm_select },
          { name: :security_policy }
        ]
      end

      define_attr_accessors

      # @!attribute selinux_mode
      #   @return [String] SELinux mode to be used
      # @!attribute lsm_select
      #   @return [String] Major Linux Security Module to be used.
      #     Possible values: apparmor, selinux, none
      # @!attribute security_policy
      #   @return [SecurityPolicy] Security policy section

      # Constructor
      #
      # @param parent [SectionWithAttributes] Parent section
      def initialize(parent = nil)
        super
        @security_policy = SecurityPolicySection.new
      end

      # Method used by {.new_from_hashes} to populate the attributes.
      #
      # @param hash [Hash] see {.new_from_hashes}
      def init_from_hashes(hash)
        super
        return unless hash.key?("security_policy")

        @security_policy = SecurityPolicySection.new_from_hashes(hash["security_policy"], self)
      end
    end
  end
end
