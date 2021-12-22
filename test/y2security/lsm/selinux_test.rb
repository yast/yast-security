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
require "y2security/lsm/selinux"

describe Y2Security::LSM::Selinux do
  subject { described_class.new }

  let(:installation_mode) { false }

  let(:product_features) do
    {
      "globals" => {
        "lsm" => {
          "default" => "selinux",
          "selinux" => {
            "mode"         => selinux_mode,
            "configurable" => selinux_configurable,
            "patterns"     => selinux_patterns
          }
        }
      }
    }
  end

  let(:wsl) { false }

  let(:selinux_mode) { "enforcing" }
  let(:selinux_configurable) { false }
  let(:selinux_patterns) { nil }

  let(:security_param)  { :missing }
  let(:selinux_param)   { :missing }
  let(:enforcing_param) { :missing }
  let(:lsm_param)       { :missing }

  let(:disabled_mode) { Y2Security::LSM::Selinux::Mode.find(:disabled) }
  let(:permissive_mode) { Y2Security::LSM::Selinux::Mode.find(:permissive) }
  let(:enforcing_mode) { Y2Security::LSM::Selinux::Mode.find(:enforcing) }

  let(:configured_mode) { enforcing_mode }

  let(:read_only_root_fs) { false }

  before do
    Yast::ProductFeatures.Import(product_features)

    allow(Yast::Arch).to receive(:is_wsl).and_return(wsl)
    allow(Yast::Stage).to receive(:initial).and_return(installation_mode)

    allow(Yast::Bootloader).to receive(:kernel_param).with(:common, "security")
      .and_return(security_param)
    allow(Yast::Bootloader).to receive(:kernel_param).with(:common, "selinux")
      .and_return(selinux_param)
    allow(Yast::Bootloader).to receive(:kernel_param).with(:common, "enforcing")
      .and_return(enforcing_param)
    allow(Yast::Bootloader).to receive(:kernel_param).with(:common, "lsm")
      .and_return(lsm_param)
    allow(subject).to receive(:read_only_root_fs?).and_return(read_only_root_fs)
  end

  describe "#id" do
    it "returns :selinux" do
      expect(subject.id).to eql(:selinux)
    end
  end

  describe "#label" do
    it "returns 'SELinux'" do
      expect(subject.label).to eql("SELinux")
    end
  end

  describe "#read" do
    it "forces a read of the current SELinux mode" do
      expect(subject).to receive(:mode)

      subject.read
    end

    it "returns true" do
      expect(subject.read).to eql(true)
    end
  end

  describe "#mode" do
    let(:mode) { subject.mode }

    context "when mode is set" do
      before do
        subject.mode = :enforcing
      end

      it "returns the set mode" do
        expect(subject.mode).to eq(enforcing_mode)
      end
    end

    context "when mode is not set yet" do
      context "in a running system" do
        before do
          allow(subject).to receive(:configured_mode).and_return(configured_mode)
        end

        context "with selinux enabled" do
          let(:security_param) { "selinux" }
          let(:selinux_param) { "1" }

          context "and enforcing boot param missing" do
            let(:configured_mode) { enforcing_mode }

            it "returns the mode set by the config file" do
              expect(subject.mode).to eq(enforcing_mode)
            end
          end

          context "and both missing, the enforcing boot param and the configuration file" do
            let(:configured_mode) { nil }

            it "returns the permissive mode" do
              expect(subject.mode).to eq(permissive_mode)
            end
          end

          context "and enforcing mode set via boot param" do
            let(:enforcing_param) { "1" }
            let(:configured_mode) { permissive_mode }

            it "returns the enforcing mode" do
              expect(subject.mode).to eq(enforcing_mode)
            end
          end

          context "and permissive mode set via boot param" do
            let(:enforcing_param) { "0" }
            let(:configured_mode) { enforcing_mode }

            it "returns the permissive mode" do
              expect(subject.mode).to eq(permissive_mode)
            end
          end
        end

        context "with selinux disabled" do
          let(:security_param) { "selinux" }
          let(:selinux_param) { "0" }

          it "returns the disabled mode" do
            expect(subject.mode).to eq(disabled_mode)
          end
        end
      end

      context "during installation" do
        let(:installation_mode) { true }

        context "when globals => selinux => mode feature is not set" do
          let(:selinux_mode) { "" }

          it "returns the :disabled mode" do
            expect(mode.id).to eq(:disabled)
          end
        end

        context "when globals => selinux => mode is set" do
          context "and contains a valid mode" do
            let(:selinux_mode) { "enforcing" }

            it "returns the defined mode" do
              expect(mode.id).to eq(:enforcing)
            end
          end

          context "but contains a not valid mode" do
            let(:selinux_mode) { "enforced" }

            it "returns the :disabled mode" do
              expect(mode.id).to eq(:disabled)
            end
          end
        end
      end
    end
  end

  describe "#configured_mode" do
    let(:config_file) { double("CFA::Selinux", load: true, selinux: selinux_mode) }

    before do
      allow(subject).to receive(:config_file).and_return(config_file)
    end

    context "when enforcing mode is configured" do
      let(:selinux_mode) { "enforcing" }

      it "returns the enforcing mode" do
        expect(subject.configured_mode).to eq(enforcing_mode)
      end
    end

    context "when permissive mode is configured" do
      let(:selinux_mode) { "permissive" }

      it "returns the permissive mode" do
        expect(subject.configured_mode).to eq(permissive_mode)
      end
    end

    context "when unknown mode is configured" do
      let(:selinux_mode) { "whatever" }

      it "returns nil" do
        expect(subject.configured_mode).to be_nil
      end
    end
  end

  describe "#running_mode" do
    let(:getenforce_cmd) { ["/usr/sbin/getenforce", stdout: :capture] }
    let(:cheetah_error) { Cheetah::ExecutionFailed.new([], "", nil, nil) }

    context "when getenforce tool is available" do
      let(:getenforce_output) { "Enforcing\n" }

      before do
        allow(Yast::Execute).to receive(:locally!).with(*getenforce_cmd)
          .and_return(getenforce_output)
      end

      it "it returns the running Selinux::Mode" do
        expect(subject.running_mode).to be_a(Y2Security::LSM::Selinux::Mode)
        expect(subject.running_mode.id).to eq(:enforcing)
      end
    end

    context "when getenforce tool is not available" do
      before do
        allow(Yast::Execute).to receive(:locally!).with(*getenforce_cmd)
          .and_raise(cheetah_error)
      end

      it "logs the exception message" do
        expect(subject.log).to receive(:info).with(cheetah_error.message)

        subject.running_mode
      end

      it "returns nil" do
        expect(subject.running_mode).to be_nil
      end
    end
  end

  describe "#boot_mode" do
    context "when security boot param is not set" do
      it "returns the disabled mode" do
        expect(subject.boot_mode).to eq(disabled_mode)
      end
    end

    context "when security boot param is not selinux" do
      let(:security_param) { "smack" }

      it "returns the disabled mode" do
        expect(subject.boot_mode).to eq(disabled_mode)
      end
    end

    context "when security boot param is selinux" do
      let(:security_param) { "selinux" }

      context "and selinux boot param is zero" do
        let(:selinux_param) { "0" }

        it "returns the disabled mode" do
          expect(subject.boot_mode).to eq(disabled_mode)
        end
      end

      context "and selinux boot param is a text" do
        let(:selinux_param) { "whatever" }

        it "returns the disabled mode" do
          expect(subject.boot_mode).to eq(disabled_mode)
        end
      end

      context "and selinux boot param is negative number" do
        let(:selinux_param) { -1 }

        it "returns the disabled mode" do
          expect(subject.boot_mode).to eq(disabled_mode)
        end
      end

      context "and selinux boot param is greater than zero" do
        let(:selinux_param) { "1" }

        context "and enforcing param is zero" do
          let(:enforcing_param) { 0 }

          it "returns the permissive mode" do
            expect(subject.boot_mode).to eq(permissive_mode)
          end
        end

        context "and enforcing param is greater than zero" do
          let(:enforcing_param) { "1" }

          it "returns the enforcing mode" do
            expect(subject.boot_mode).to eq(enforcing_mode)
          end
        end

        context "but enforcing param is not defined" do
          it "returns nil" do
            expect(subject.boot_mode).to be_nil
          end
        end

        context "but enforcing param is a negative value" do
          let(:enforcing_param) { "-15" }

          it "returns nil" do
            expect(subject.boot_mode).to be_nil
          end
        end
      end
    end
  end

  describe "#mode=" do
    context "when a known SELinux mode id is given" do
      it "returns the mode" do
        expect(subject).to receive(:mode=).with(:permissive).and_return(permissive_mode)

        subject.mode = permissive_mode.id
      end

      it "sets the mode" do
        subject.mode = permissive_mode.id

        expect(subject.mode).to eq(permissive_mode)
      end
    end

    context "when an unknown SELinux id is given" do
      it "logs an error" do
        expect(subject.log).to receive(:error).with(/.*not found.*disabled.*/)

        subject.mode = :whatever
      end
      it "uses the disabled mode" do
        subject.mode = :whatever

        expect(subject.mode).to eq(disabled_mode)
      end
    end

    context "when nil is given" do
      it "uses the disabled mode" do
        subject.mode = :not_now

        expect(subject.mode).to eq(disabled_mode)
      end
    end
  end

  describe "#modes" do
    it "returns a collection of known SELinux modes" do
      expect(subject.modes).to all(be_a(Y2Security::LSM::Selinux::Mode))
    end

    it "contains known mode ids" do
      expect(subject.modes.map(&:id)).to eq([:disabled, :permissive, :enforcing])
    end

    it "contains known mode names" do
      expect(subject.modes.map(&:name)).to eq(["Disabled", "Permissive", "Enforcing"])
    end
  end

  describe "#save" do
    let(:write_result) { true }
    let(:selinux_configurable) { true }
    let(:mode) { enforcing_mode }
    let(:config_file) { double("CFA::Selinux", load: true, save: true, :selinux= => true) }
    let(:executor) { double("Yast::Execute", on_target!: "") }

    before do
      allow(Yast::Bootloader).to receive(:modify_kernel_params)
      allow(Yast::Bootloader).to receive(:Write).and_return(write_result)
      allow(Yast::Execute).to receive(:stdout).and_return(executor)
      allow(subject).to receive(:config_file).and_return(config_file)
      allow(subject).to receive(:mode).and_return(mode)

      subject.mode = enforcing_mode
    end

    context "when running in installation mode" do
      let(:installation_mode) { true }

      it "does not write the bootloader configuration" do
        expect(Yast::Bootloader).to_not receive(:Write)

        subject.save
      end

      context "and SELinux can be configured" do
        it "modifies the bootloader kernel params" do
          expect(Yast::Bootloader).to receive(:modify_kernel_params)
            .with(enforcing_mode.options)

          subject.save
        end

        it "changes the mode in the configuration file" do
          expect(config_file).to receive(:selinux=).with("enforcing")
          expect(config_file).to receive(:save)

          subject.save
        end

        context "and root filesystem will be mounted read-only" do
          let(:read_only_root_fs) { true }

          it "touches .autorelable file" do
            expect(executor).to receive(:on_target!).with(/rm/, /autorelabel/)
            expect(executor).to receive(:on_target!).with(/touch/, /autorelabel/)

            subject.save
          end

          context "but SELinux is disabled" do
            let(:mode) { disabled_mode }

            it "does not touch .autorelable file" do
              expect(executor).to_not receive(:on_target!).with(/rm/, /autorelabel/)
              expect(executor).to_not receive(:on_target!).with(/touch/, /autorelabel/)

              subject.save
            end
          end
        end

        context "and root filesystem will not be mounted as read-only" do
          it "does not touch the .autorelable file" do
            expect(executor).to_not receive(:on_target!).with(/rm/, /autorelabel/)
            expect(executor).to_not receive(:on_target!).with(/touch/, /autorelabel/)

            subject.save
          end
        end

        it "returns true" do
          expect(subject.save).to eq(true)
        end
      end

      context "but SELinux cannot be configurable" do
        let(:selinux_configurable) { false }

        it "does not modify the bootloader kernel params" do
          expect(Yast::Bootloader).to_not receive(:modify_kernel_params)

          subject.save
        end

        it "does not change the mode in the configuration file" do
          expect(config_file).to_not receive(:selinux=)
          expect(config_file).to_not receive(:save)

          subject.save
        end

        it "does not touch the .autorelable file" do
          expect(executor).to_not receive(:on_target!).with(/rm/, /autorelabel/)
          expect(executor).to_not receive(:on_target!).with(/touch/, /autorelabel/)

          subject.save
        end

        it "does not write the bootloader configuration" do
          expect(Yast::Bootloader).to_not receive(:Write)

          subject.save
        end

        it "returns false" do
          expect(subject.save).to eq(false)
        end
      end
    end

    context "when running in an installed system" do
      it "modifies the bootloader kernel params" do
        expect(Yast::Bootloader).to receive(:modify_kernel_params)
          .with(enforcing_mode.options)

        subject.save
      end

      it "writes the bootloader configuration" do
        expect(Yast::Bootloader).to receive(:Write)

        subject.save
      end

      it "changes the mode in the configuration file" do
        expect(config_file).to receive(:selinux=).with("enforcing")
        expect(config_file).to receive(:save)

        subject.save
      end

      it "does not touch the .autorelable file" do
        expect(executor).to_not receive(:on_target!).with(/rm/, /autorelabel/)
        expect(executor).to_not receive(:on_target!).with(/touch/, /autorelabel/)

        subject.save
      end

      context "and configuration has been successfully written" do
        it "returns true" do
          expect(subject.save).to eq(true)
        end
      end

      context "and configuration has not been written" do
        let(:write_result) { false }

        it "returns false" do
          expect(subject.save).to eq(false)
        end
      end
    end
  end

  describe "#needed_patterns" do
    let(:mode) { permissive_mode }

    before do
      allow(subject).to receive(:mode).and_return(mode)
    end

    context "when globals => selinux => patterns is set" do
      let(:selinux_patterns) { "one-pattern another-pattern" }

      it "returns an array holding defined patterns" do
        expect(subject.needed_patterns).to eq(["one-pattern", "another-pattern"])
      end

      context "but selected Disabled SELinux mode" do
        let(:mode) { disabled_mode }

        it "returns an empty array" do
          expect(subject.needed_patterns).to eq([])
        end
      end
    end

    context "when globals => selinux => patterns is not set" do
      it "returns an empty array" do
        expect(subject.needed_patterns).to eq([])
      end
    end
  end

  describe "#configurable?" do
    context "when running in a WSL environment" do
      let(:wsl) { true }

      it "returns false" do
        expect(subject.configurable?).to eq(false)
      end
    end

    context "when running in an installed system" do
      it "returns true" do
        expect(subject.configurable?).to eq(true)
      end
    end

    context "when running in installation" do
      let(:installation_mode) { true }

      context "and 'selinux_configurable' is true" do
        let(:selinux_configurable) { true }

        it "returns true" do
          expect(subject.configurable?).to eq(true)
        end
      end

      context "and 'selinux_configurable' is false" do
        it "returns false" do
          expect(subject.configurable?).to eq(false)
        end
      end
    end
  end
end

describe Y2Security::LSM::Selinux::Mode do
  subject { described_class }

  describe ".all" do
    it "returns a collection of known modes" do
      expect(subject.all).to all(be_an(Y2Security::LSM::Selinux::Mode))
    end
  end

  describe ".kernel_options" do
    it "includes 'enforcing'" do
      expect(subject.kernel_options).to include("enforcing")
    end
  end

  describe ".find" do
    let(:mode) { subject.find(mode_id) }

    context "when given a known mode id" do
      let(:mode_id) { "permissive" }

      it "returns the mode" do
        expect(mode).to be_an(Y2Security::LSM::Selinux::Mode)
        expect(mode.id).to eq(mode_id.to_sym)
      end
    end

    context "when given an unknown mode id" do
      let(:mode_id) { "not_known" }

      it "returns nil" do
        expect(mode).to be_nil
      end
    end
  end

  describe "#id" do
    let(:mode) { described_class.find("enforcing") }

    it "returns the mode id" do
      expect(mode.id).to eq(:enforcing)
    end
  end

  describe "#name" do
    let(:mode) { described_class.find(:permissive) }

    it "returns the mode name" do
      expect(mode.name).to eq("Permissive")
    end
  end

  describe "#options" do
    let(:mode) { described_class.find(:disabled) }

    it "returns the mode options" do
      expect(mode.options).to a_hash_including("security", "selinux", "enforcing")
    end
  end
end
