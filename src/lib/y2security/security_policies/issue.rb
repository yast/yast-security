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
    # Represents an issue related to a security policy
    #
    # An issue can have an associated action to remedy the issue.
    #
    # @example Create an issue with no associated action
    #   issue = Issue.new(_("The bootloader does not have a password"))
    #   issue.action #=> nil
    #
    # @example Create an issue with an associated action
    #   action = Action.new(_("enable the firewall")) do
    #     Installation::SecuritySettings.enable_firewall!
    #   end
    #   issue = Issue.new(_("The firewall is not enabled"), action)
    #   issue.fix
    class Issue
      # TODO: use a real identifier?
      # @return [Integer] Issue identifier
      attr_reader :id

      # @return [String] Textual description of the issue
      attr_reader :message

      # @return [Action] Remediation action
      attr_reader :action

      class << self
        def next_id
          @id ||= 0
          @id += 1
        end
      end

      # @param message [String] Issue message
      # @param action [Action] Action to remedy the issue
      def initialize(message, action = nil)
        @id = self.class.next_id
        @message = message
        @action = action
      end

      # Determines whether the issue has an remediation action
      #
      # @return [Boolean]
      def action?
        !!@action
      end

      # Fixes the problem by running the action
      def fix
        @action&.run
      end
    end
  end
end
