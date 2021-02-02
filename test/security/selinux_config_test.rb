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

require_relative "../test_helper"

require "security/selinux_config"

describe Security::SelinuxConfig do
  subject { described_class.new }
  let(:installation_mode) { false }
  let(:default_mode) { "enforcing" }

  before do
    allow(Yast::Mode).to receive(:installation).and_return(installation_mode)
    allow(Yast::ProductFeatures).to receive(:GetFeature).with("globals", "selinux_mode")
      .and_return(default_mode)
  end

  RSpec.shared_examples 'initial mode' do
    context "in a running system" do
      before do
        allow(Yast::Bootloader).to receive(:kernel_param).with(:common, "security")
          .and_return(security_module)
        allow(Yast::Bootloader).to receive(:kernel_param).with(:common, "selinux")
          .and_return(selinux_status)
        allow(Yast::Bootloader).to receive(:kernel_param).with(:common, "enforcing")
          .and_return(selinux_enforcing)
      end

      context "with a SELinux configuration" do
        let(:security_module) { "selinux" }
        let(:selinux_status) { "1" }
        let(:selinux_enforcing) { "0" }

        it "returns the configured mode" do
          expect(subject.initial_mode).to eq(:permissive)
        end
      end

      context "without a SELinux configuration" do
        let(:security_module) { "apparmor" }
        let(:selinux_status) { :missing }
        let(:selinux_enforcing) { :missing }

        it "returns :disabled" do
          expect(subject.initial_mode).to eq(:disabled)
        end
      end
    end

    context "during installation" do
      let(:installation_mode) { true }

      it "returns the default proposed mode" do
        expect(subject.initial_mode).to eq(default_mode.to_sym)
      end
    end
  end

  describe "initial_mode" do
    include_examples "initial mode"
  end

  describe "#mode" do
    context "when mode has not been changed yet" do
      include_examples "initial mode"
    end

    context "when mode has been changed" do
      before do
        subject.mode = :disabled
      end

      context "in a running system" do
        it "returns the chosen mode" do
          expect(subject.mode).to eq(:disabled)
        end
      end

      context "during the installation" do
        let(:installation_mode) { true }

        it "returns the chosen mode" do
          expect(subject.mode).to eq(:disabled)
        end
      end
    end

  end

  describe "#mode=" do
    context "when a symbol or string given" do
      it "sets it as a current mode" do
        subject.mode = :permissive
        expect(subject.mode).to eq(:permissive)

        subject.mode = "whatever"
        expect(subject.mode).to eq(:whatever)
      end
    end

    context "when nil is given" do
      it "sets current mode as :disabled" do
        subject.mode = nil
        expect(subject.mode).to eq(:disabled)
      end
    end
  end

  describe "#available_modes" do
    it "returns all known SELinux modes" do
      modes = subject.available_modes
      mode_ids = modes.map { |m| m[:id] }

      expect(mode_ids).to eq([:disabled, :permissive, :enforcing])
    end
  end

  describe "#running_mode=" do
    let(:getenforce_cmd) { ["/usr/sbin/getenforce", stdout: :capture] }
    let(:cheetah_error) { Cheetah::ExecutionFailed.new([], "", nil, nil) }

    context "when getenforce tool is available" do
      before do
        allow(Yast::Execute).to receive(:locally!).with(*getenforce_cmd).and_return("Enforcing\n")
      end

      it "returns its sanitize output as a symbol" do
        expect(subject.running_mode).to eq(:enforcing)
      end
    end

    context "when getenforce tool is not available" do
      before do
        allow(Yast::Execute).to receive(:locally!).with(*getenforce_cmd)
          .and_raise(cheetah_error)
      end

      it "logs a debug message" do
        expect(subject.log).to receive(:debug).with(/.*getenforce.*not available/)

        subject.running_mode
      end

      it "returns :disabled" do
        expect(subject.running_mode).to eq(:disabled)
      end
    end
  end

  describe "#save" do
    before do
      allow(Yast::Bootloader).to receive(:Write).and_return(true)
    end

    RSpec.shared_examples "does not change the mode" do
    end

    context "when working with a known mode" do
      context "that is already set" do
        before do
          subject.mode = :permissive
          subject.save
          subject.mode = :permissive
        end

        it "returns false" do
          expect(subject.save).to eq(false)
        end

        it "does not write bootloader configuration" do
          expect(Yast::Bootloader).to_not receive(:Write)

          subject.save
        end
      end

      context "that is not set yet" do
        before do
          subject.mode = :permissive
          subject.save
          subject.mode = :disabled
        end

        it "returns true" do
          expect(subject.save).to eq(true)
        end

        it "modifies kernel params" do
          expect(Yast::Bootloader).to receive(:modify_kernel_params)

          subject.save
        end

        context "in a running system" do
          it "writes bootloader configuration" do
            expect(Yast::Bootloader).to receive(:Write)

            subject.save
          end
        end

        context "during installation" do
          let(:installation_mode) { true }

          it "does not write bootloader configuration" do
            expect(Yast::Bootloader).to_not receive(:Write)

            subject.save
          end
        end
      end
    end

    context "when set mode is unknonw" do
      before do
        subject.mode = :unknown
      end

      it "returns false" do
        expect(subject.save).to eq(false)
      end

      it "does not modify kernel params" do
        expect(Yast::Bootloader).to_not receive(:modify_kernel_params)

        subject.save
      end

      it "does not write bootloader configuration" do
        expect(Yast::Bootloader).to_not receive(:Write)

        subject.save
      end
    end
  end
end
