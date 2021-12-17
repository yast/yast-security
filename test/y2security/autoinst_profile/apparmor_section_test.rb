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
require "y2security/autoinst_profile"

describe Y2Security::AutoinstProfile::ApparmorSection do
  let(:profile) do
    {
      "configurable" => true,
      "selectable"   => false,
      "patterns"     => "apparmor_pattern"
    }
  end

  describe ".new_from_hashes" do
    it "sets the section attributes" do
      section = described_class.new_from_hashes(profile)
      expect(section.configurable).to eq(true)
      expect(section.selectable).to eq(false)
      expect(section.patterns).to eq("apparmor_pattern")
    end
  end
end
