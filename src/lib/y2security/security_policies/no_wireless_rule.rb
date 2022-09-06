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
require "y2security/security_policies/rule"
require "y2security/security_policies/action"
require "y2security/security_policies/issue"

module Y2Security
  module SecurityPolicies
    # Rule to deactivate wireless network interfaces (SLES-15-010380).
    class NoWirelessRule < Rule
      def initialize
        super("SLES-15-010380", :network)
      end

      # @param config [Y2Network::Config] Network configuration to check
      # @see Rule#validate
      def validate(config = nil)
        config ||= default_config
        return [] if config.nil?

        wireless = find_wireless_connections(config)
        return nil if wireless.empty?

        names = wireless.map(&:name)
        Issue.new(
          format(_("Wireless network interfaces must be deactivated: %s"), names),
          action: action_for(config, names),
          scope:  :network
        )
      end

    private

      # Returns wireless connections which are not disabled
      #
      # @return [Array<Y2Network::ConnectionConfig::Wireless]
      def find_wireless_connections(config)
        config.connections.select do |conn|
          conn.is_a?(Y2Network::ConnectionConfig::Wireless) &&
            conn.startmode&.name != "off"
        end
      end

      # Build an action to disable a connection
      #
      # @param config [Y2Network::Config] Network configuration
      # @param conn   [Array<Y2Network::ConnectionConfig>]
      def action_for(config, names)
        Action.new(_(format("disable wireless interfaces"))) do
          names.each do |name|
            conn = config.connections.by_name(name)
            next if conn.nil?

            conn.startmode = Y2Network::Startmode.create("off")
            config.add_or_update_connection_config(conn)
          end
        end
      end

      # Default network configuration
      #
      # @return [Y2Network::Config,nil]
      def default_config
        Yast.import "Lan"
        Yast::Lan.yast_config
      end
    end
  end
end
