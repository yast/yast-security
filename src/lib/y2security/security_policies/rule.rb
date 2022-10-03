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

require "yast"

module Y2Security
  module SecurityPolicies
    # Represents a rule for a security policy
    #
    # It is expected to redefined the #pass? and, optionally, #fixable? and #fix? methods in the
    # derived classes.
    class Rule
      include Yast::I18n

      # Rule ID
      #
      # Contains the rule ID as defined by the SCAP Security Guided without the prefix
      # "xccdf_org.ssgproject.content_rule_".
      # For example, for a rule with ID "xccdf_org.ssgproject.content_rule_partition_for_home" the
      # value would be "partition_for_home".
      #
      # @return [String]
      attr_reader :id

      # Rule identifiers (e.g., "CCE-85639-3")
      #
      # @return [Array<String>]
      attr_reader :identifiers

      # Rule references (e.g., "SLES-15-040200", "SV-235004r622137_rule", etc)
      #
      # @return [Array<String>]
      attr_reader :references

      # @return [String] Rule description
      attr_reader :description

      # @return [Symbol] Scope to apply the rule to
      attr_reader :scope

      # @param id [String] See {#id}
      # @param identifiers [Array<String>] See {#identifiers}
      # @param references [Array<String>] See {#references}
      # @param description [String] See {#description}
      # @param scope [Symbol] See {#scope}
      def initialize(id, identifiers: [], references: [], description: nil, scope: nil)
        @id = id
        @identifiers = identifiers
        @references = references
        @description = description
        @scope = scope
        @enabled = true
      end

      # Enables the rule
      #
      # If the rule is enabled, it will be used when checking a profile.
      def enable
        @enabled = true
      end

      # Disables the rule
      #
      # If the rule is disabled, it will be skipped when checking a profile.
      def disable
        @enabled = false
      end

      # Determines whether the rule is enabled or not
      #
      # @return [Boolean] true if the rule is enabled; false otherwise
      def enabled?
        @enabled
      end

      # Determines whether the rule passes or not.
      # *target_config* is a {TargetConfig}.
      def pass?(_target_config)
        true
      end

      # Determines whether the rule can be automatically fixed
      def fixable?
        false
      end

      # Automatically fixes the system to make the rule pass.
      # *target_config* is a {TargetConfig}.
      def fix(_target_config)
        nil
      end
    end
  end
end
