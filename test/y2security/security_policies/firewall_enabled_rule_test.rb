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
require "y2security/security_policies/firewall_enabled_rule"
require "y2security/security_policies/target_config"
require "y2network/config"

describe Y2Security::SecurityPolicies::FirewallEnabledRule do
  let(:target_config) do
    instance_double(Y2Security::SecurityPolicies::TargetConfig, security: security_config)
  end

  let(:security_config) do
    instance_double("Installation::SecuritySettings", enable_firewall: enabled)
  end

  let(:enabled) { true }

  describe "#id" do
    it "returns the rule ID" do
      expect(subject.id).to eq("SLES-15-010220")
    end
  end

  describe "#pass?" do
    context "when the firewall is enabled" do
      it "returns true" do
        expect(subject.pass?(target_config)).to eq(true)
      end
    end

    context "when the firewall is not enabled " do
      let(:enabled) { false }

      it "returns false" do
        expect(subject.pass?(target_config)).to eq(false)
      end
    end
  end

  describe "#fixable?" do
    it "returns true" do
      expect(subject).to be_fixable
    end
  end

  describe "#fix" do
    it "enables the firewall" do
      expect(target_config.security).to receive(:enable_firewall!)
      subject.fix(target_config)
    end
  end
end
