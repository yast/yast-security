# Copyright (c) [2022] SUSE LLC
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
require "y2security/security_policies/bootloader_password_rule"
require "y2security/security_policies/target_config"

describe Y2Security::SecurityPolicies::BootloaderPasswordRule do
  before do
    allow(Y2Storage::Arch).to receive(:new).and_return(arch)
  end

  let(:arch) { instance_double(Y2Storage::Arch, efiboot?: efiboot) }

  let(:efiboot) { true }

  let(:bootloader) { Bootloader::NoneBootloader.new }

  describe "#name" do
    context "in a UEFI system" do
      let(:efiboot) { true }

      it "returns grub2_uefi_password" do
        expect(subject.name).to eq("grub2_uefi_password")
      end
    end

    context "in a non-UEFI system" do
      let(:efiboot) { false }

      it "returns grub2_password" do
        expect(subject.name).to eq("grub2_password")
      end
    end
  end

  describe "#id" do
    context "in a UEFI system" do
      let(:efiboot) { true }

      it "returns SLES-15-010200" do
        expect(subject.id).to eq("SLES-15-010200")
      end
    end

    context "in a non-UEFI system" do
      let(:efiboot) { false }

      it "returns SLES-15-010190" do
        expect(subject.id).to eq("SLES-15-010190")
      end
    end
  end

  describe "#pass?" do
    let(:target_config) do
      instance_double(Y2Security::SecurityPolicies::TargetConfig, bootloader: bootloader)
    end

    context "when no Grub based bootloader is selected" do
      it "returns true" do
        expect(subject.pass?(target_config)).to eq(true)
      end
    end

    context "when a Grub based bootloader is selected" do
      let(:bootloader) { Bootloader::Grub2.new }
      let(:password) { "test.pass" }
      let(:restricted) { true }

      before do
        if password
          bootloader.password.used = true
          bootloader.password.unrestricted = !restricted
        end
      end

      context "and a password is set and menu editing is restricted" do
        it "returns true" do
          expect(subject.pass?(target_config)).to eq(true)
        end
      end

      context "and no password is set" do
        let(:password) { false }

        it "returns false" do
          expect(subject.pass?(target_config)).to eq(false)
        end
      end

      context "and the menu editing is not restricted" do
        let(:restricted) { false }

        it "returns false" do
          expect(subject.pass?(target_config)).to eq(false)
        end
      end
    end
  end
end
