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
require "y2security/lsm/none"

describe Y2Security::LSM::None do
  describe "#id" do
    it "returns the symbol :none" do
      expect(subject.id).to eql(:none)
    end
  end

  describe "#label" do
    it "returns the string 'None'" do
      expect(subject.label).to eql("None")
    end
  end

  describe "#kernel_params" do
    it "returns a Hash" do
      expect(subject.kernel_params).to be_a(Hash)
    end

    it "includes the key 'lsm' with all known minor modules string as the value" do
      expect(subject.kernel_params).to include("lsm" => "integrity")
    end
  end

  describe "#kernel_options" do
    it "returns an array with the boot options for changing the LSM to be used" do
      expect(subject.kernel_options).to eq(["security", "lsm"])
    end
  end
end
