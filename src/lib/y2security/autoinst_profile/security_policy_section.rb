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
    #   <security_policies t="list">
    #     <listitem>
    #       <name>disa_stig</name>
    #       <disabled_rules t="list">
    #         <listitem>encrypt_partitions</listitem>
    #       </disabled_rules>
    #     </listitem>
    #   </security_policies>
    class SecurityPolicySection < ::Installation::AutoinstProfile::SectionWithAttributes
      def self.attributes
        [
          { name: :name },
          { name: :disabled_rules }
        ]
      end

      define_attr_accessors

      # @!attribute name
      #   @return [String] Policy name to apply
      # @!attribute disabled_rules
      #   @return [Array<String>] Name of the rules to ignore

      def initialize(parent = nil)
        super
        @disabled_rules = []
      end

      # Method used by {.new_from_hashes} to populate the attributes.
      #
      # @param hash [Hash] see {.new_from_hashes}
      def init_from_hashes(hash)
        super
        @disabled_rules = hash["disabled_rules"] || []
      end
    end
  end
end
