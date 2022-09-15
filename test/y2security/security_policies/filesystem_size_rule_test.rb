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
require "y2security/security_policies/filesystem_size_rule"
require "y2security/security_policies/target_config"
require "y2storage"

describe Y2Security::SecurityPolicies::FilesystemSizeRule do
  subject { described_class.new("SLES-15-030660", "/var/log/audit", min_size) }

  let(:min_size) { Y2Storage::DiskSize.MiB(100) }

  describe "#id" do
    it "returns the rule ID" do
      expect(subject.id).to eq("SLES-15-030660")
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

    context "when there is no a file system for the given path" do
      before do
        subvolume = filesystem.btrfs_subvolumes.find { |s| s.mount_path == "/var" }
        subvolume.mount_path = "/var/log/audit"
      end

      it "returns false" do
        expect(subject.pass?(target_config)).to eq(false)
      end
    end

    context "when there is a file system for the given path" do
      before do
        # Filesystem is over a 1 TiB partition
        filesystem.mount_path = "/var/log/audit"
      end

      context "and the size of the device is less than the given minimun size" do
        let(:min_size) { Y2Storage::DiskSize.TiB(2) }

        it "returns false" do
          expect(subject.pass?(target_config)).to eq(false)
        end
      end

      context "and the size of the device is equal to the given minimun size" do
        let(:min_size) { devicegraph.find_by_name("/dev/sda2").size }

        it "returns true" do
          expect(subject.pass?(target_config)).to eq(true)
        end
      end

      context "and the size of the device is greater than the given minimun size" do
        let(:min_size) { Y2Storage::DiskSize.TiB(0.5) }

        it "returns true" do
          expect(subject.pass?(target_config)).to eq(true)
        end
      end
    end
  end

  describe "#fixable?" do
    it "returns false" do
      expect(subject).to_not be_fixable
    end
  end
end
