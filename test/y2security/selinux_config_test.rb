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
require "y2security/selinux_config"

describe Y2Security::SelinuxConfig do
  subject { described_class.new }

  let(:installation_mode) { false }

  before do
    allow(Yast::Mode).to receive(:installation).and_return(installation_mode)
  end

  describe "initialize" do
    let(:mode) { subject.mode }

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

        it "sets the proper mode" do
          expect(mode.id).to eq(:permissive)
        end
      end

      context "without a SELinux configuration" do
        let(:security_param) { "apparmor" }
        let(:selinux_param) { :missing }
        let(:enforcing_param) { :missing }

        it "sets the :disabled mode" do
          expect(mode.id).to eq(:disabled)
        end
      end
    end

    context "during installation" do
      let(:installation_mode) { true }

      before do
        allow(Yast::ProductFeatures).to receive(:GetFeature)
          .with("globals", "selinux_mode")
          .and_return(proposed_mode)
      end

      context "when 'selinux_mode' is not present" do
        let(:proposed_mode) { "" }

        it "sets the :disabled mode" do
          expect(mode.id).to eq(:disabled)
        end
      end

      context "when 'selinux_mode' is present" do
        context "and contains a valid mode id" do
          let(:proposed_mode) { :enforcing }

          it "sets the proper mode" do
            expect(mode.id).to eq(:enforcing)
          end
        end

        context "but contains a not valid mode id" do
          let(:proposed_mode) { :enforced }

          it "sets the :disabled mode" do
            expect(mode.id).to eq(:disabled)
          end
        end
      end
    end
  end

  describe "#needed_packages" do
    let(:release_name) { "openSUSE Leap" }

    before do
      allow(Yast::OSRelease).to receive(:ReleaseName).and_return(release_name)
    end

    it "includes 'selinux-tools'" do
      expect(subject.needed_packages).to include('selinux-tools')
    end

    it "includes 'selinux-policy-targeted'" do
      expect(subject.needed_packages).to include('selinux-policy-targeted')
    end

    context "when running in a SLE Micro OS" do
      let(:release_name) { "SLE Micro OS" }

      it "includes 'micro-selinux'" do
        expect(subject.needed_packages).to include('microos-selinux')
      end
    end

    context "when not running in a SLE Micro OS" do
      it "includes 'selinux'" do
        expect(subject.needed_packages).to include('selinux')
      end

      it "does not include 'micro-selinux'" do
        expect(subject.needed_packages).to_not include('micro-selinux')
      end
    end
  end

  describe "#mode" do
    let(:enforcing_mode) { Y2Security::SelinuxConfig::Mode.find(:enforcing) }

    before do
      subject.mode = enforcing_mode
    end

    it "returns the set mode" do
      expect(subject.mode).to eq(enforcing_mode)
    end
  end

  describe "#mode=" do
    let(:disabled_mode) { Y2Security::SelinuxConfig::Mode.find(:disabled) }
    let(:permissive_mode) { Y2Security::SelinuxConfig::Mode.find(:permissive) }

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
      it "uses the disabled mode" do
        subject.mode = :not_now

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
        expect(subject.running_mode).to be_a(Y2Security::SelinuxConfig::Mode)
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

  describe "#modes" do
    it "returns a collection of known SELinux modes" do
      expect(subject.modes).to all(be_a(Y2Security::SelinuxConfig::Mode))
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
    let(:enforcing_mode) { Y2Security::SelinuxConfig::Mode.find(:enforcing) }
    let(:selinux_configurable) { true }

    before do
      allow(Yast::Bootloader).to receive(:modify_kernel_params)
      allow(Yast::Bootloader).to receive(:Write).and_return(write_result)
      allow(Yast::ProductFeatures).to receive(:GetBooleanFeature)
        .with("globals", "selinux_configurable")
        .and_return(selinux_configurable)

      subject.mode = enforcing_mode
    end

    context "when running in installation mode" do
      let(:installation_mode) { true }

      it "does not write the configuration" do
        expect(Yast::Bootloader).to_not receive(:Write)

        subject.save
      end

      context "and SELinux can be configured" do
        it "modifies the bootloader kernel params" do
          expect(Yast::Bootloader).to receive(:modify_kernel_params)
            .with(enforcing_mode.options)

          subject.save
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

  describe "#configurable?" do
    let(:selinux_configurable) { true }

    before do
      allow(Yast::ProductFeatures).to receive(:GetBooleanFeature)
        .with("globals", "selinux_configurable")
        .and_return(selinux_configurable)
    end

    context "when running in an installed system" do
      it "returns true" do
        expect(subject.configurable?).to eq(true)
      end
    end

    context "when running in installation" do
      let(:installation_mode) { true }

      context "and 'selinux_configurable' is true" do
        it "returns true" do
          expect(subject.configurable?).to eq(true)
        end
      end

      context "and 'selinux_configurable' is false" do
        let(:selinux_configurable) { false }

        it "returns false" do
          expect(subject.configurable?).to eq(false)
        end
      end
    end
  end
end

describe Y2Security::SelinuxConfig::Mode do
  subject { described_class }

  describe ".all" do
    it "returns a collection of known modes" do
      expect(subject.all).to all(be_an(Y2Security::SelinuxConfig::Mode))
    end
  end

  describe ".kernel_options" do
    it "includes 'security'" do
      expect(subject.kernel_options).to include("security")
    end

    it "includes 'selinux'" do
      expect(subject.kernel_options).to include("selinux")
    end

    it "includes 'enforcing'" do
      expect(subject.kernel_options).to include("enforcing")
    end
  end

  describe ".find" do
    let(:mode) { subject.find(mode_id) }

    context "when given a known mode id" do
      let(:mode_id) { "permissive" }

      it "returns the mode" do
        expect(mode).to be_an(Y2Security::SelinuxConfig::Mode)
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
