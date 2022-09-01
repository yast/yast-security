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
require_relative "./policy_examples"
require "y2security/security_policies/disa_stig_policy"

describe Y2Security::SecurityPolicies::DisaStigPolicy do
  include_examples "Y2Security::SecurityPolicies::Policy"

  describe "#validate" do
    context "when validating the network scope" do
      let(:scope) { Y2Security::SecurityPolicies::Scopes::Network.new(config: network_config) }

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
        issues = subject.validate(scope)
        expect(issues.size).to eq(1)

        issue = issues.first

        expect(issue.message).to match(/Wireless network interfaces/)
        expect(issue.message).to include("wlan0")
        expect(issue.message).to_not include("wlan1")
        expect(issue.scope).to eq(scope)
      end
    end

    context "when validating the storage scope" do
      let(:scope) { Y2Security::SecurityPolicies::Scopes::Storage.new(devicegraph: devicegraph) }

      let(:devicegraph) { Y2Storage::StorageManager.instance.staging }

      context "when there are not-encrypted and mounted file systems" do
        before do
          fake_storage_scenario("plain.yml")
        end

        it "returns an issue for missing encryption" do
          issues = subject.validate(scope)

          expect(issues.map(&:message)).to include(an_object_matching(/not encrypted: \/, swap/))
          expect(issues.map(&:scope)).to all(eq(scope))
        end

        it "the issue does not include /boot/efi" do
          issues = subject.validate(scope)

          expect(issues.map(&:message))
            .to_not include(an_object_matching(/not encrypted:.*efi.*/))
        end
      end

      context "when all mounted file systems are encrypted" do
        before do
          fake_storage_scenario("gpt_encryption.yml")
        end

        it "does not return an issue for missing encryption" do
          issues = subject.validate(scope)

          expect(issues.map(&:message))
            .to_not include(an_object_matching(/not encrypted/))
        end
      end

      context "when /home and/or /var mount points are missing" do
        before do
          fake_storage_scenario("plain.yml")
        end

        it "returns an issue for missing mount points" do
          issues = subject.validate(scope)

          expect(issues.map(&:message))
            .to include(an_object_matching(/must be a separate mount point for: \/home, \/var/))
          expect(issues.map(&:scope)).to all(eq(scope))
        end
      end

      context "when neither /home nor /var mount points are missing" do
        before do
          fake_storage_scenario("plain.yml")

          sda1 = devicegraph.find_by_name("/dev/sda1")
          sda1.mount_point.path = "/home"

          sda3 = devicegraph.find_by_name("/dev/sda3")
          sda3.mount_point.path = "/var"
        end

        it "does not return an issue for missing mount points" do
          issues = subject.validate(scope)

          expect(issues.map(&:message))
            .to_not include(an_object_matching(/must be a separate mount point/))
        end
      end
    end
  end

  context "when validating the firewall scope" do
    let(:scope) do
      Y2Security::SecurityPolicies::Scopes::Firewall.new(security_settings: security_settings)
    end

    let(:security_settings) do
      instance_double("Installation::SecuritySettings", enable_firewall: enabled)
    end

    let(:enabled) { true }

    context "and the firewall is enabled" do
      it "returns no issues" do
        issues = subject.validate(scope)
        expect(issues).to be_empty
      end
    end

    context "and the firewall is not enabled " do
      let(:enabled) { false }

      it "returns an issue pointing that the firewall is not enabled" do
        issues = subject.validate(scope)
        expect(issues.size).to eq(1)

        issue = issues.first

        expect(issue.message).to include("Firewall is not enabled")
        expect(issue.scope).to eq(scope)
      end
    end
  end

  context "when validating the bootloader scope" do
    let(:scope) { Y2Security::SecurityPolicies::Scopes::Bootloader.new(bootloader: bootloader) }

    let(:bootloader) { Bootloader::NoneBootloader.new }

    context "and no Grub based bootloader is selected" do
      it "returns no issues" do
        issues = subject.validate(scope)
        expect(issues).to be_empty
      end
    end

    context "and a Grub based bootloader is selected" do
      let(:bootloader) { Bootloader::Grub2.new }
      let(:password) { nil }
      let(:unrestricted) { false }

      before do
        if password
          bootloader.password.used = true
          bootloader.password.unrestricted = unrestricted
        end
      end

      context "when a password is not set" do
        it "returns an issue pointing that the bootloader password must be set" do
          issues = subject.validate(scope)
          expect(issues.size).to eq(2)

          issue = issues.first
          expect(issue.message).to include("Bootloader password must be set")
          expect(issue.scope).to eq(scope)
        end
      end

      context "when a password is set" do
        let(:password) { "test.pass" }

        context "and the menu editing is restricted" do
          it "returns no issues" do
            issues = subject.validate(scope)
            expect(issues).to be_empty
          end
        end

        context "and the menu editing is not restricted" do
          let(:unrestricted) { true }

          it "returns an issue pointing that the bootloader menu editing" \
             " must be set as restricted" do
            issues = subject.validate(scope)
            expect(issues.size).to eq(1)

            issue = issues.first

            expect(issue.message).to include("Bootloader menu editing must be set as restricted")
            expect(issue.scope).to eq(scope)
          end
        end
      end
    end
  end
end
