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

  let(:target_config) do
    instance_double(Y2Security::SecurityPolicies::TargetConfig)
  end

  describe "#rules" do

    before do
      allow(Y2Storage::Arch).to receive(:new).and_return(arch)
    end

    let(:arch) { instance_double(Y2Storage::Arch, efiboot?: true) }

    it "checks whether /home is on a separate mount point" do
      rule = subject.rules.find do |mp|
        mp.is_a?(Y2Security::SecurityPolicies::MissingMountPointRule) &&
          mp.mount_point == "/home"
      end
      expect(rule).to_not be_nil
    end

    it "checks whether /var is on a separate mount point" do
      rule = subject.rules.find do |mp|
        mp.is_a?(Y2Security::SecurityPolicies::MissingMountPointRule) &&
          mp.mount_point == "/var"
      end
      expect(rule).to_not be_nil
    end

    it "checks whether /var/log/audit is on a separate file system" do
      rule = subject.rules.find do |r|
        r.is_a?(Y2Security::SecurityPolicies::SeparateFilesystemRule) &&
          r.mount_path == "/var/log/audit"
      end
      expect(rule).to_not be_nil
    end

    it "checks whether the file system for /var/log/audit is big enough" do
      rule = subject.rules.find do |r|
        r.is_a?(Y2Security::SecurityPolicies::SeparateFilesystemRule) &&
          r.mount_path == "/var/log/audit"
      end
      expect(rule).to_not be_nil
    end

    it "checks whether the file system is encrypted" do
      expect(subject.rules)
        .to include(Y2Security::SecurityPolicies::MissingEncryptionRule)
    end

    it "checks that no wireless rules will be active" do
      expect(subject.rules)
        .to include(Y2Security::SecurityPolicies::NoWirelessRule)
    end

    it "checks that the firewall will be enabled" do
      expect(subject.rules)
        .to include(Y2Security::SecurityPolicies::FirewallEnabledRule)
    end

    it "checks that the bootloader is password-protected and restricted" do
      expect(subject.rules)
        .to include(Y2Security::SecurityPolicies::BootloaderPasswordRule)
    end
  end
end
