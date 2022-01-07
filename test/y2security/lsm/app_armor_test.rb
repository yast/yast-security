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
require "y2security/lsm/app_armor"

describe Y2Security::LSM::AppArmor do
  describe "#id" do
    it "returns the symbol :apparmor" do
      expect(subject.id).to eql(:apparmor)
    end
  end

  describe "#label" do
    it "returns the string AppArmor" do
      expect(subject.label).to eql("AppArmor")
    end
  end

  describe "#kernel_params" do
    it "returns a Hash" do
      expect(subject.kernel_params).to be_a(Hash)
    end

    it "includes the key 'security' with the 'apparmor' value" do
      expect(subject.kernel_params).to include("security" => "apparmor")
    end
  end
end
