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

module Y2Security
  module SecurityPolicies
    # Helper class to keep the list of issues for each policy
    class IssuesCollection
      def initialize
        @issues = {}
      end

      # Updates the issues of a policy
      #
      # @param policy [Policy]
      # @param issues [Array<Issue>]
      def update(policy, issues)
        @issues[policy] = issues
      end

      # Issues for the given policy
      #
      # @param policy [Policy]
      # @return [Array<Issue>]
      def by_policy(policy)
        @issues[policy] || []
      end

      # All issues
      #
      # @return [Array<Issue>]
      def all
        @issues.values.flatten
      end

      # Hash representation of the collection
      #
      # @return [Hash]
      def to_h
        @issues.dup
      end
    end

    # Represents an issue related to a security policy
    #
    # An issue can have an associated action to remedy the issue and a scope.
    #
    # @example Create an issue without associated action nor scope
    #   issue = Issue.new(_("The bootloader does not have a password"))
    #   issue.action  #=> nil
    #   issue.scope   #=> nil
    #
    # @example Create an issue with an associated action and scope
    #   action = Action.new(_("enable the firewall")) do
    #     Installation::SecuritySettings.enable_firewall!
    #   end
    #   scope = Scopes::Storage.new
    #   issue = Issue.new(_("The firewall is not enabled"), action: action, scope: scope)
    #   issue.fix
    class Issue
      # Textual description of the issue
      #
      # @return [String]
      attr_reader :message

      # Remediation action
      #
      # @return [Action]
      attr_reader :action

      # Scope of the issue
      #
      # @return [Scopes::Storage, Scopes::Bootloader, Scopes::Network, Scopes::Firewall, nil]
      attr_reader :scope

      # @param message [String] Issue message
      # @param action [Action] Action to remedy the issue
      # @param scope [Scopes::Storage, Scopes::Bootloader, Scopes::Network, Scopes::Firewall, nil]
      def initialize(message, action: nil, scope: nil)
        @message = message
        @action = action
        @scope = scope
      end

      # Determines whether the issue has a remediation action
      #
      # @return [Boolean]
      def action?
        !!@action
      end

      # Whether the issue has a scope
      #
      # @return [Boolean]
      def scope?
        !!@scope
      end

      # Fixes the problem by running the action
      def fix
        @action&.run
      end
    end
  end
end
