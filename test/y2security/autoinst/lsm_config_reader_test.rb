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
  subject { described_class.new(section) }
  let(:lsm) { Y2Security::LSM::Config.instance }
  let(:profile) { { "lsm_select" => "apparmor" } }
  let(:section) { Y2Security::AutoinstProfile::SecuritySection.new_from_hashes(profile) }

  before do
    lsm.reset
  end

  describe "#read" do
    context "when a LSM is selected" do
      it "selects the desired LSM accordingly" do
        expect { subject.read }.to change { lsm.selected&.id }.from(nil).to(:apparmor)
      end
    end

    context "when a LSM is not selected explicitly but selinux_mode is given" do
      let(:profile) { { "selinux_mode" => "disabled" } }

      it "selects SELinux as the desired LSM" do
        expect { subject.read }.to change { lsm.selected&.id }.from(nil).to(:selinux)
      end

      it "sets the SELinux mode" do
        subject.read
        expect(lsm.selinux.mode.id).to eql(:disabled)
      end
    end
  end
end
