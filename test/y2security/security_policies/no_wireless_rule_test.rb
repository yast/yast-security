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
require "y2security/security_policies/target_config"
require "y2network/config"

describe Y2Security::SecurityPolicies::NoWirelessRule do
  let(:target_config) do
    instance_double(Y2Security::SecurityPolicies::TargetConfig, network: network_config)
  end

  let(:network_config) { Y2Network::Config.new(source: :wicked, connections: connections) }
  let(:connections) { [] }

  let(:wlan0_conn) do
    Y2Network::ConnectionConfig::Wireless.new.tap do |conn|
      conn.interface = "wlan0"
      conn.name = "wlan0"
    end
  end

  let(:wlan1_conn) do
    Y2Network::ConnectionConfig::Wireless.new.tap do |conn|
      conn.interface = "wlan1"
      conn.name = "wlan1"
      conn.startmode = Y2Network::Startmode.create("off")
    end
  end

  describe "#pass?" do
    context "when wireless devices are configured to be active" do
      let(:connections) do
        Y2Network::ConnectionConfigsCollection.new([wlan0_conn, wlan1_conn])
      end

      it "returns false" do
        expect(subject.pass?(target_config)).to eq(false)
      end
    end

    context "when no wireless devices are configured to be active" do
      let(:connections) do
        Y2Network::ConnectionConfigsCollection.new([wlan1_conn])
      end

      it "returns true" do
        expect(subject.pass?(target_config)).to eq(true)
      end
    end
  end

  describe "#fixable?" do
    it "returns true" do
      expect(subject).to be_fixable
    end
  end

  describe "#fix" do
    let(:eth0_conn) do
      Y2Network::ConnectionConfig::Ethernet.new.tap do |conn|
        conn.interface = "eth0"
        conn.name = "eth0"
        conn.startmode = Y2Network::Startmode.create("auto")
      end
    end

    let(:connections) do
      Y2Network::ConnectionConfigsCollection.new([eth0_conn, wlan0_conn])
    end

    it "disables wireless devices" do
      subject.fix(target_config)
      network = target_config.network
      eth0 = network.connections.by_name("eth0")
      wlan0 = network.connections.by_name("wlan0")
      expect(eth0.startmode).to eq(Y2Network::Startmode.create("auto"))
      expect(wlan0.startmode).to eq(Y2Network::Startmode.create("off"))
    end
  end
end
