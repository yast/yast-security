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
    # Represents an action to remedy a security policy issue
    #
    # @example Define an action to run wireless connections
    #   action = Action.new(_("Disable wireless interfaces")) do
    #     Yast::Lan.yast_config.connections.each do |conn|
    #       next unless conn.is_a?(Y2Network::ConnectionConfig::Wireless)
    #
    #       conn.startmode = Y2Network::Startmode.create("off")
    #     end
    #   end
    #
    # TODO: undo
    class Action
      # @return [String] Textual description of the action
      attr_reader :message

      # @param message [String] Action message
      # @param block [Proc] Code to remedy the issue
      def initialize(message, &block)
        @message = message
        @block = block
      end

      # Runs the action
      def run
        @block.call
      end
    end
  end
end
