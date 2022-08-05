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

require_relative "../test_helper"
require "y2security/stig_validator"

describe Y2Security::StigValidator do
  describe "#validate" do
    context "when validating the network scope" do
      before do
        allow(Yast::Lan).to receive(:yast_config).and_return(network_config)
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

      let(:connections) do
        Y2Network::ConnectionConfigsCollection.new([wlan0_conn, wlan1_conn])
      end
      let(:network_config) { Y2Network::Config.new(source: :wicked, connections: connections) }

      it "returns an issue per each active wireless connection" do
        issues = subject.issues(:network)
        expect(issues.size).to eq(1)
        expect(issues.first.message).to match(/No wireless/)
      end
    end
  end
end
