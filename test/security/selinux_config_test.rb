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
  let(:proposed_mode) { "enforcing" }

  before do
    allow(Yast::Mode).to receive(:installation).and_return(installation_mode)
    allow(Yast::ProductFeatures).to receive(:GetFeature).with("globals", "selinux_mode")
      .and_return(proposed_mode)
  end

  RSpec.shared_examples 'initial mode' do
    let(:mode) { subject.initial_mode }

    context "in a running system" do
      before do
        allow(Yast::Bootloader).to receive(:kernel_param).with(:common, "security")
          .and_return(security_param)
        allow(Yast::Bootloader).to receive(:kernel_param).with(:common, "selinux")
          .and_return(selinux_param)
        allow(Yast::Bootloader).to receive(:kernel_param).with(:common, "enforcing")
          .and_return(enforcing_param)
      end

      context "with a SELinux configuration" do
        let(:security_param) { "selinux" }
        let(:selinux_param) { "1" }
        let(:enforcing_param) { "0" }

        it "returns the configured mode" do
          expect(mode.id).to eq(:permissive)
        end
      end

      context "without a SELinux configuration" do
        let(:security_param) { "apparmor" }
        let(:selinux_param) { :missing }
        let(:enforcing_param) { :missing }

        it "returns the :disabled mode" do
          expect(mode.id).to eq(:disabled)
        end
      end
    end

    context "during installation" do
      let(:installation_mode) { true }

      it "returns the proposed mode" do
        expect(mode.id).to eq(proposed_mode.to_sym)
      end
    end
  end

  describe "initial_mode" do
    include_examples "initial mode"
  end

  describe "#modes" do
    it "returns a collection of known SELinux modes" do
      expect(subject.modes).to all(be_a(Security::SelinuxConfig::Mode))
    end

    it "contains known mode ids" do
      expect(subject.modes.map(&:id)).to eq([:disabled, :permissive, :enforcing])
    end

    it "contains known mode names" do
      expect(subject.modes.map(&:name)).to eq(["Disabled", "Permissive", "Enforcing"])
    end
  end

  describe "#mode" do
    context "when a known SELinux mode is set" do
      before do
        subject.mode = :enforcing
      end

      it "returns it" do
        expect(subject.mode).to be_a(Security::SelinuxConfig::Mode)
        expect(subject.mode.id).to eq(:enforcing)
      end
    end

    context "when an unknown SELinux was set" do
      before do
        subject.mode = :not_known
      end

      it "returns nil" do
        expect(subject.mode).to be_nil
      end
    end
  end

  describe "#mode=" do
    context "when a known SELinux id is given" do
      it "sets the new mode" do
        subject.mode = :permissive

        expect(subject.mode).to be_a(Security::SelinuxConfig::Mode)
        expect(subject.mode.id).to eq(:permissive)
      end
    end

    context "when an unknown SELinux id is given" do
      it "unsets the mode" do
        subject.mode = :not_now

        expect(subject.mode).to be_nil
      end
    end

    context "when nil is given" do
      it "unsets the mode" do
        subject.mode = :not_now

        expect(subject.mode).to be_nil
      end
    end
  end

  describe "#running_mode" do
    let(:getenforce_cmd) { ["/usr/sbin/getenforce", stdout: :capture] }
    let(:cheetah_error) { Cheetah::ExecutionFailed.new([], "", nil, nil) }

    context "when getenforce tool is available" do
      let(:getenforce_output) { "Enforcing\n"  }

      before do
        allow(Yast::Execute).to receive(:locally!).with(*getenforce_cmd)
          .and_return(getenforce_output)
      end

      it "it returns the running SelinuxConfig::Mode" do
        expect(subject.running_mode).to be_a(Security::SelinuxConfig::Mode)
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

      it "returns the :disabled mode" do
        expect(subject.running_mode.id).to eq(:disabled)
      end
    end
  end

  describe "#save" do
    before do
      allow(Yast::Bootloader).to receive(:Write).and_return(true)
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
          subject.mode = :enforcing
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

describe Security::SelinuxConfig::Mode do
  subject { described_class }

  describe ".all" do
    it "returns a collection of known modes" do
      expect(subject.all).to all(be_an(Security::SelinuxConfig::Mode))
    end
  end

  describe ".find" do
    let(:mode) { subject.find(mode_id) }

    context "when given a known mode id" do
      let(:mode_id) { "permissive" }

      it "returns the mode" do
        expect(mode).to be_an(Security::SelinuxConfig::Mode)
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

  describe ".match" do
    let(:security_param) { nil }
    let(:selinux_param) { nil }
    let(:enforcing_param) { nil }

    let(:params) do
      {  "security" => security_param, "selinux" => selinux_param, "enforcing" => enforcing_param  }
    end

    let(:mode) { subject.match(params) }

    context "when 'security' is not 'selinux'" do
      let(:security_param) { "apparmor" }
      let(:selinux_param) { "1" }

      it "returns the :disabled mode" do
        expect(mode.id).to eq(:disabled)
      end
    end

    context "when 'security' is 'selinux'" do
      let(:security_param) { "selinux" }

      context "and 'selinux' is missing" do
        it "returns the :disabled mode" do
          expect(mode.id).to eq(:disabled)
        end
      end

      context "and 'selinux' is a number greater than zero" do
        let(:selinux_param) { "1" }

        it "returns the :permissive mode" do
          expect(mode.id).to eq(:permissive)
        end

        context "but 'enforcing' is a number greater than zero" do
          let(:enforcing_param) { "1" }

          it "returns the :enforcing mode" do
            expect(mode.id).to eq(:enforcing)
          end
        end
      end

      context "but 'selinux' is zero" do
        let(:selinux_param) { "0" }
        let(:enforcing_param) { "1" }

        it "returns the :disabled mode" do
          expect(mode.id).to eq(:disabled)
        end
      end
    end
  end
end
