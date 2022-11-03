#!/usr/bin/env rspec
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
require "y2security/autoinst_profile/security_policy_section"

describe Y2Security::AutoinstProfile::SecurityPolicySection do
  describe ".new_from_hashes" do
    let(:profile) do
      { "action" => "remediate", "enabled_policies" => ["stig"] }
    end

    it "sets the SCAP action and the list of enabled policies" do
      section = described_class.new_from_hashes(profile)
      expect(section.action).to eq("remediate")
      expect(section.enabled_policies).to eq(["stig"])
    end

    context "an empty profile" do
      it "returns an empty section" do
        section = described_class.new_from_hashes({})
        expect(section.action).to be_nil
        expect(section.enabled_policies).to eq([])
      end
    end
  end
end
