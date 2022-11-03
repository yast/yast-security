#!/usr/bin/env rspec
# Copyright (c) [2021] SUSE LLC
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
require "y2security/autoinst_profile/security_section"

describe Y2Security::AutoinstProfile::SecuritySection do
  describe ".new_from_hashes" do
    let(:profile) { { "selinux_mode" => "enforcing", "lsm_select" => "selinux" } }

    it "sets the supported attributes" do
      section = described_class.new_from_hashes(profile)
      expect(section.selinux_mode).to eql("enforcing")
      expect(section.lsm_select).to eql("selinux")
      expect(section.security_policies.action).to be_nil
      expect(section.security_policies.enabled_policies).to be_empty
    end

    context "when a list of security policies is given" do
      let(:profile) do
        {
          "security_policies" => {
            "action" => "remediate", "enabled_policies" => ["stig"]
          }
        }
      end

      it "adds one section for each policy" do
        section = described_class.new_from_hashes(profile)
        policy_section = section.security_policies
        expect(policy_section.action).to eq("remediate")
        expect(policy_section.parent).to eq(section)
      end
    end
  end
end
