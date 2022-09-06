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

require_relative "../../test_helper"
require "y2security/security_policies/no_wireless_rule"
require "y2network/config"

describe Y2Security::SecurityPolicies::NoWirelessRule do
  describe "#validate" do
    let(:network_config) { Y2Network::Config.new(source: :wicked, connections: connections) }

    let(:connections) do
      Y2Network::ConnectionConfigsCollection.new([wlan0_conn, wlan1_conn])
    end

    let(:wlan0_conn) do
      Y2Network::ConnectionConfig::Wireless.new.tap do |conn|
        conn.interface = "wlan0"
        conn.name = "wlan0"
        # conn.startmode = Y2Network::Startmode.create("off")
      end
    end

    let(:wlan1_conn) do
      Y2Network::ConnectionConfig::Wireless.new.tap do |conn|
        conn.interface = "wlan1"
        conn.name = "wlan1"
        conn.startmode = Y2Network::Startmode.create("off")
      end
    end

    it "returns an issue per each active wireless connection" do
      issue = subject.validate(network_config)

      expect(issue.message).to match(/Wireless network interfaces/)
      expect(issue.message).to include("wlan0")
      expect(issue.message).to_not include("wlan1")
      expect(issue.scope).to eq(:network)
    end
  end
end
