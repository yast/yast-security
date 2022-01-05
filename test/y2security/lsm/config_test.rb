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
  let(:globals_section) { { "globals" => { "lsm" => lsm_section } } }
  let(:lsm_section) do
    {
      "select"       => "selinux",
      "configurable" => lsm_configurable,
      "selinux"      => {
        "mode"         => selinux_mode,
        "configurable" => selinux_configurable,
        "selectable"   => selinux_selectable,
        "patterns"     => selinux_patterns
      }
    }
  end

  let(:select) { "selinux" }
  let(:lsm_configurable) { true }
  let(:selinux_mode) { "enforcing" }
  let(:selinux_configurable) { false }
  let(:selinux_selectable) { true }
  let(:selinux_patterns) { nil }
  subject { described_class.instance }

  before do
    subject.reset
    Yast::ProductFeatures.Import(globals_section)
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
      active = subject.active
      expect(active.size).to eql(1)
      expect(active.first.id).to eql(:selinux)
    end

    context "when no supported LSM is active" do
      let(:active_modules) { "lockdown,capabilities,tomoyo" }

      it "returns an empty array" do
        expect(subject.active).to eq([])
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
      expect(subject.from_system.id).to eq(:apparmor)
    end
  end

  describe ".supported" do
    it "returns an array with an instance of all the supported LSM" do
      supported = subject.supported
      expect(supported.map(&:id).sort).to eql([:apparmor, :none, :selinux])
    end
  end

  describe ".reset" do
    it "resets the memoized object state" do
      supported = subject.supported
      expect(supported).to eql(subject.supported)
      subject.reset
      expect(supported).to_not eql(subject.supported)
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
      expect { subject.select(:apparmor) }
        .to change { subject.selected&.id }.from(nil).to(:apparmor)
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

  describe "#read" do
    let(:normal) { true }
    let(:from_system) { subject.supported.find { |m| m.id == :selinux } }

    before do
      allow(Yast::Stage).to receive(:normal).and_return(normal)
      allow(subject).to receive(:from_system).and_return(from_system)
      allow(from_system).to receive(:read) if from_system
    end

    context "when called in running system" do
      it "selects the active module" do
        expect { subject.read }.to change { subject.selected&.id }.from(nil).to(:selinux)
      end

      it "reads the selected LSM config" do
        expect(from_system).to receive(:read)
        subject.read
      end

      context "and no module is selected" do
        let(:from_system) { nil }

        it "returns false" do
          expect(subject.read).to eql(false)
        end
      end
    end

    context "when not called in a running system" do
      let(:normal) { false }

      it "returns false" do
        expect(subject.read).to eql(false)
      end
    end
  end

  describe "#propose_default" do
    context "when Linux Security module is declared as configurable in the control file" do
      it "selects the LSM to be used based on the control file" do
        expect { subject.propose_default }.to change { subject.selected&.id }.from(nil).to(:selinux)
      end

      context "when no default LSM is declared in the control file" do
        let(:lsm_section) { { "configurable" => lsm_configurable } }

        it "fallbacks to :apparmor" do
          expect { subject.propose_default }
            .to change { subject.selected&.id }.from(nil).to(:apparmor)
        end
      end
    end

    context "when Linux Security module is not declared as configurable in the control file" do
      let(:lsm_configurable) { false }

      it "does not select any module by default" do
        expect { subject.propose_default }.to_not(change { subject.selected })
      end
    end
  end

  describe "#configurable?" do
    context "when LSM is declared in the profile as not configurable" do
      let(:lsm_configurable) { false }

      it "returns false" do
        expect(subject.configurable?).to eql(false)
      end
    end

    it "returns true" do
      expect(subject.configurable?).to eql(true)
    end
  end

  describe "needed_patterns" do
    let(:lsm_section) do
      {
        "select"   => "apparmor",
        "apparmor" => {
          "patterns" => "microos_apparmor"
        }
      }
    end

    it "returns the needed patterns for the selected LSM" do
      subject.propose_default
      expect(subject.needed_patterns).to eql(["microos_apparmor"])
    end

    it "returns an empty array if no LSM is selected" do
      expect(subject.needed_patterns).to eql([])
    end
  end

  describe "#save" do
    before do
      allow_any_instance_of(Y2Security::LSM::Base).to receive(:reset_kernel_params)
    end

    it "resets the kernel parameters of all supported modules" do
      subject.propose_default
      allow(subject.selected).to receive(:save)
      subject.supported.each { |m| expect(m).to receive(:reset_kernel_params) }

      subject.save
    end

    it "saves the selected LSM configuration" do
      subject.propose_default
      expect(subject.selected).to receive(:save).and_return(true)
      subject.save
    end

    context "when no LSM is selected" do
      it "returns false" do
        expect(subject.selected).to eq(nil)
        expect(subject.save).to eql(false)
      end
    end
  end
end
