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

require "y2security/security_policies/rule"
require "y2network/connection_config"
require "y2network/startmode"

module Y2Security
  module SecurityPolicies
    # Rule to deactivate wireless network interfaces (SLES-15-010380).
    class NoWirelessRule < Rule
      def initialize
        textdomain "security"

        # TRANSLATORS: Security policy rule
        description = _("Wireless network interfaces must be deactivated")

        super("wireless_disable_interfaces",
          id: "SLES-15-010380", description: description, scope: :network)
      end

      # @see Rule#pass?
      def pass?(target_config)
        wireless = find_wireless_connections(target_config.network)
        wireless.empty?
      end

      # @see Rule#fixable?
      def fixable?
        true
      end

      # Build an action to disable a connection
      #
      # @see Rule#fix
      def fix(target_config)
        config = target_config.network

        find_wireless_connections(config).each do |conn|
          conn.startmode = Y2Network::Startmode.create("off")
          config.add_or_update_connection_config(conn)
        end
      end

    private

      # Returns wireless connections which are not disabled
      #
      # @return [Array<Y2Network::ConnectionConfig::Wireless]
      def find_wireless_connections(config)
        return [] unless config

        config.connections.select do |conn|
          conn.is_a?(Y2Network::ConnectionConfig::Wireless) &&
            conn.startmode&.name != "off"
        end
      end
    end
  end
end
