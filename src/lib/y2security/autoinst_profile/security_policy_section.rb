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

require "installation/autoinst_profile/section_with_attributes"

module Y2Security
  module AutoinstProfile
    # This class represents the <security_policy> section of an AutoYaST profile
    #
    # @example Enabling DISA STIG except one of the rules
    #   <security_policy>
    #     <action>none</action>
    #     <name>stig</name>
    #   </security_policy>
    class SecurityPolicySection < ::Installation::AutoinstProfile::SectionWithAttributes
      def self.attributes
        [
          { name: :action },
          { name: :policy }
        ]
      end

      define_attr_accessors

      # @!attribute action
      #   @return [String,nil] SCAP action to apply on first boot ("none", "scan" or "remediate")
      # @!attribute policy
      #   @return [String,nil] Enabled policy
    end
  end
end
