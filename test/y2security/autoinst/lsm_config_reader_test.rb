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
require "y2security/autoinst/lsm_config_reader"

describe Y2Security::Autoinst::LSMConfigReader do
  subject { described_class.new(section.lsm) }
  let(:lsm) { Y2Security::LSM::Config.instance }
  let(:profile) do
    {
      "lsm" => {
        "select"       => "selinux",
        "configurable" => true,
        "selinux"      => {
          "mode"         => "enforcing",
          "configurable" => false,
          "selectable"   => true,
          "patterns"     => "selinux_pattern"
        },
        "apparmor"     => {
          "configurable" => true,
          "selectable"   => false,
          "patterns"     => "apparmor_pattern"
        },
        "none"         => {
          "selectable" => false
        }
      }
    }
  end
  let(:section) { Y2Security::AutoinstProfile::SecuritySection.new_from_hashes(profile) }

  before do
    lsm.reset
  end

  describe "#read" do
    it "modifies the LSMConfig based on the lsm section" do
      expect { subject.read }.to change { lsm.selected&.id }.from(nil).to(:selinux)
        .and change { lsm.configurable }.from(nil).to(true)
    end

    context "when it contains a section for some of the supported modules" do
      it "modifies the module internal configuration" do
        subject.read
        selinux = lsm.selinux

        expect(selinux.mode.id.to_s).to eql("enforcing")
        expect(selinux.configurable).to eql(false)
        expect(selinux.selectable).to eql(true)
        expect(selinux.needed_patterns).to eql(["selinux_pattern"])

        apparmor = lsm.apparmor

        expect(apparmor.configurable).to eql(true)
        expect(apparmor.selectable).to eql(false)
        expect(apparmor.needed_patterns).to eql(["apparmor_pattern"])

        none = lsm.none
        expect(none.selectable).to eql(false)
      end
    end
  end
end
