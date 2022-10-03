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
require "y2security/security_policies/separate_filesystem_rule"
require "y2security/security_policies/target_config"

describe Y2Security::SecurityPolicies::SeparateFilesystemRule do
  subject do
    described_class.new("partition_for_var_log_audit", "/var/log/audit",
      identifiers: ["CCE-85618-7"],
      references:  ["SLES-15-030810"])
  end

  describe "#id" do
    it "returns the rule ID" do
      expect(subject.id).to eq("partition_for_var_log_audit")
    end
  end

  describe "identifiers" do
    it "returns the rule identifiers" do
      expect(subject.identifiers).to contain_exactly("CCE-85618-7")
    end
  end

  describe "#references" do
    it "returns the rule references" do
      expect(subject.references).to contain_exactly("SLES-15-030810")
    end
  end

  describe "#pass?" do
    before do
      fake_storage_scenario("btrfs.yml")

      allow(Y2Security::SecurityPolicies::TargetConfig).to receive(:new).and_return(target_config)
    end

    let(:target_config) do
      instance_double(Y2Security::SecurityPolicies::TargetConfig, storage: devicegraph)
    end

    let(:devicegraph) { Y2Storage::StorageManager.instance.staging }

    let(:filesystem) { devicegraph.find_by_name("/dev/sda2").filesystem }

    context "when there is no separate file system for the given path" do
      before do
        subvolume = filesystem.btrfs_subvolumes.find { |s| s.mount_path == "/var" }
        subvolume.mount_path = "/var/log/audit"
      end

      it "returns false" do
        expect(subject.pass?(target_config)).to eq(false)
      end
    end

    context "when there is a separate file system for the given path" do
      before do
        filesystem.mount_path = "/var/log/audit"
      end

      it "returns true" do
        expect(subject.pass?(target_config)).to eq(true)
      end
    end
  end

  describe "#fixable?" do
    it "returns false" do
      expect(subject).to_not be_fixable
    end
  end
end
