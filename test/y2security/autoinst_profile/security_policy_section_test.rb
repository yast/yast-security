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
      { "name" => "disa_stig", "disabled_rules" => ["partition_for_home"] }
    end

    it "sets the name and the list of ignored rules" do
      section = described_class.new_from_hashes(profile)
      expect(section.name).to eq("disa_stig")
      expect(section.disabled_rules).to eq(["partition_for_home"])
    end

    context "an empty profile" do
      it "returns an empty section" do
        section = described_class.new_from_hashes({})
        expect(section.name).to be_nil
        expect(section.disabled_rules).to eq([])
      end
    end
  end
end
