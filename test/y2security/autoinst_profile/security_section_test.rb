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

describe Y2Security::AutoinstProfile::SecuritySection do
  let(:profile) { { "lsm" => { "select" => "selinux" } } }

  describe ".new_from_hashes" do
    it "sets the lsm section" do
      section = described_class.new_from_hashes(profile)
      lsm = section.lsm
      expect(lsm).to be_a(Y2Security::AutoinstProfile::LSMSection)
      expect(lsm.select).to eq("selinux")
      expect(lsm.parent).to eq(section)
    end

    context "when used the old 'selinux_mode' attribute" do
      let(:profile) { { "selinux_mode" => "enforcing" } }

      it "sets the selinux_mode attribute" do
        section = described_class.new_from_hashes(profile)
        expect(section.selinux_mode).to eql("enforcing")
      end

      it "sets the lsm section as it was declared with selinux in that mode" do
        section = described_class.new_from_hashes(profile)
        lsm = section.lsm
        expect(lsm).to be_a(Y2Security::AutoinstProfile::LSMSection)
        expect(lsm.select).to eq("selinux")
        expect(lsm.parent).to eq(section)
        selinux = lsm.selinux
        expect(selinux.mode).to eq("enforcing")
      end
    end
  end
end
