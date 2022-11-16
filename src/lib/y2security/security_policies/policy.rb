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

require "y2security/security_policies/target_config"

module Y2Security
  module SecurityPolicies
    # Base class for security policies
    class Policy
      include Yast::I18n

      # Id of the policiy
      #
      # @return [Symbol]
      attr_reader :id

      # Name of the policy
      #
      # @return [String]
      attr_reader :name

      # @param id [Symbol]
      # @param name [String]
      def initialize(id, name)
        @id = id
        @name = name
      end

      # @param config [TargetConfig] Configuration to check
      # @param scope [Symbol, nil] Scope to check (nil means that all scopes must be checked)
      # @param include_disabled [Boolean] Whether disabled rules should be checked
      # @return [Array<Rule>] Failing rules for the given config and scope
      def failing_rules(config, scope: nil, include_disabled: false)
        rules
          .select { |r| scope.nil? || r.scope == scope }
          .select { |r| include_disabled || r.enabled? }
          .reject { |r| r.pass?(config) }
      end

      def rules
        []
      end
    end
  end
end
