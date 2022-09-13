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
require "y2security/security_policies/target_config"
Yast.import "Lan"
require "singleton"

describe Y2Security::SecurityPolicies::TargetConfig do
  describe "#new" do
    before do
      allow(Y2Storage::StorageManager).to receive(:instance)
        .and_return(storage_manager)
      allow(Yast::Lan).to receive(:yast_config)
        .and_return(network)
      allow(::Bootloader::BootloaderFactory).to receive(:current)
        .and_return(bootloader)
      allow(Installation::SecuritySettings).to receive(:instance)
        .and_return(security)
      # Avoid yast2-installation cyclic dependency
      allow_any_instance_of(described_class).to receive(:require).with("installation/security_settings")
    end

    let(:storage_manager) do
      instance_double(Y2Storage::StorageManager, staging: staging)
    end
    let(:staging) { instance_double(Y2Storage::Devicegraph) }
    let(:network) { instance_double(Y2Network::Config) }
    let(:bootloader) { instance_double(Bootloader::BootloaderFactory) }
    let(:security) { instance_double(Installation::SecuritySettings) }

    it "creates the configuration including the staging devicegraph" do
      config = described_class.new
      expect(config.storage).to eq(staging)
    end

    it "creates the configuration including the bootloader configuration" do
      config = described_class.new
      expect(config.bootloader).to eq(bootloader)
    end

    it "creates the configuration including the network configuration" do
      config = described_class.new
      expect(config.network).to eq(network)
    end

    it "creates the configuration including the security settings" do
      config = described_class.new
      expect(config.security).to eq(security)
    end
  end
end
