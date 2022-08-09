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
        issues = subject.validate(:network)
        expect(issues.size).to eq(1)
        message = issues.first.message
        expect(message).to match(/Wireless connections/)
        expect(message).to include("wlan0")
        expect(message).to_not include("wlan1")
      end
    end

    context "when validating the storage scope" do
      context "when a file system is not encrypted" do
        before do
          fake_storage_scenario("plain.yml")
        end

        it "returns an issue listing the unencrypted file systems" do
          issues = subject.validate(:storage)
          expect(issues.size).to eq(1)
          message = issues.first.message
          expect(message).to include "/"
          expect(message).to include "swap"
        end
      end

      context "when all file systems are encrypted" do
        before do
          fake_storage_scenario("gpt_encryption.yml")
        end

        it "returns no issue" do
          issues = subject.validate(:storage)
          expect(issues).to be_empty
        end
      end

      context "when all file systems are encrypted except /boot/efi" do
        before do
          fake_storage_scenario("efi.yml")
        end

        it "returns no issues" do
          issues = subject.validate(:storage)
          expect(issues).to be_empty
        end
      end

      context "when the file system is included in an encrypted LVM VG" do
        before do
          fake_storage_scenario("encrypted_lvm.yml")
        end

        it "returns no issues" do
          issues = subject.validate(:storage)
          expect(issues).to be_empty
        end
      end
    end
  end

  context "when validating the firewall scope" do
    let(:security_settings) { double("Installation::SecuritySettings", enable_firewall: enabled) }
    let(:enabled) { true }

    before do
      allow(subject).to receive(:security_settings).and_return(security_settings)
    end

    context "and the firewall is enabled" do
      it "returns no issues" do
        issues = subject.validate(:firewall)
        expect(issues).to be_empty
      end
    end

    context "and the firewall is not enabled " do
      let(:enabled) { false }

      it "returns an issue pointing that the firewall is not enabled" do
        issues = subject.validate(:firewall)
        expect(issues.size).to eq(1)
        expect(issues.first.message).to include("Firewall is not enabled")
      end
    end
  end
end
