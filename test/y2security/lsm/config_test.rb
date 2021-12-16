#!/usr/bin/env rspec

# Copyright (c) [2017-2021] SUSE LLC
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
require "y2security/lsm"

describe Y2Security::LSM::Config do
  let(:product_features) do
    {
      "globals" => {
        "lsm" => {
          "default" => "selinux",
          "selinux" => {
            "mode"         => selinux_mode,
            "configurable" => selinux_configurable,
            "selectable"   => selinux_selectable,
            "patterns"     => selinux_patterns
          }
        }
      }
    }
  end

  let(:selinux_mode) { "enforcing" }
  let(:selinux_configurable) { false }
  let(:selinux_selectable) { true }
  let(:selinux_patterns) { nil }

  before do
    described_class.reset
    Yast::ProductFeatures.Import(product_features)
    allow(Yast::Stage).to receive(:initial).and_return(true)
  end

  describe ".active" do
    let(:active_modules) { "lockdown,capabilities,selinux" }

    before do
      allow(Yast::SCR).to receive(:Read)
        .with(Yast.path(".target.string"), "/sys/kernel/security/lsm")
        .and_return(active_modules)
    end

    it "returns an array with all the supported and active LSM" do
      active = described_class.active
      expect(active.size).to eql(1)
      expect(active.first.id).to eql(:selinux)
    end

    context "when no supported LSM is active" do
      let(:active_modules) { "lockdown,capabilities,tomoyo" }

      it "returns an empty array" do
        expect(described_class.active).to eq([])
      end
    end
  end

  describe ".from_system" do
    let(:active_modules) { "lockdown,capabilities,apparmor" }

    before do
      allow(Yast::SCR).to receive(:Read)
        .with(Yast.path(".target.string"), "/sys/kernel/security/lsm")
        .and_return(active_modules)
    end

    it "returns the first supported and active LSM" do
      expect(described_class.from_system.id).to eq(:apparmor)
    end
  end

  describe ".supported" do
    it "returns an array with an instance of all the supported LSM" do
      supported = described_class.supported
      expect(supported.map(&:id).sort).to eql([:apparmor, :none, :selinux])
    end
  end

  describe ".reset" do
    it "resets the memoized object state" do
      supported = described_class.supported
      expect(supported).to eql(described_class.supported)
      described_class.reset
      expect(supported).to_not eql(described_class.supported)
    end
  end

  describe "#selectable" do
    let(:selinux_selectable) { false }

    it "returns an array with an instance of all the supported LSM and selectable LSM" do
      selectable = subject.selectable
      expect(selectable.map(&:id).sort).to eql([:apparmor, :none])
    end
  end

  describe "#select" do
    it "selects the LSM for the given id" do
      expect { subject.select(:apparmor) }.to change { subject.selected&.id }.from(nil).to(:apparmor)
    end

    context "when no LSM with the given id exists" do
      it "selects nothing" do
        expect { subject.select(:noexist) }.to_not(change { subject.selected&.id })
      end
    end

    context "when the LSM is not selectable according to the profile" do
      let(:selinux_selectable) { false }

      it "selects nothing" do
        expect { subject.select(:selinux) }.to_not(change { subject.selected&.id })
      end
    end
  end

  describe "#save" do
    let(:selinux_selectable) { true }
    let(:selinux_mode) { "permissive" }

    it "saves the selected LSM configuration" do
      subject.select(:selinux)
      expect(subject.selected).to receive(:save).and_return(true)
      expect(subject.save).to eql(true)
    end

    context "when no LSM is selected" do
      it "returns false" do
        expect(subject.selected).to eq(nil)
        expect(subject.save).to eql(false)
      end
    end
  end
end
