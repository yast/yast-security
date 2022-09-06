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

describe Y2Security::SecurityPolicies::BootloaderPasswordRule do
  let(:bootloader) { Bootloader::NoneBootloader.new }

  context "and no Grub based bootloader is selected" do
    it "returns no issues" do
      issue = subject.validate(bootloader)
      expect(issue).to be_nil
    end
  end

  context "and a Grub based bootloader is selected" do
    let(:bootloader) { Bootloader::Grub2.new }
    let(:password) { nil }
    let(:unrestricted) { false }

    before do
      if password
        bootloader.password.used = true
        bootloader.password.unrestricted = unrestricted
      end
    end

    context "when a password is not set" do
      it "returns an issue pointing that the bootloader password must be set" do
        issue = subject.validate(bootloader)
        expect(issue.message).to match(/Bootloader must be protected/)
        expect(issue.scope).to eq(:bootloader)
      end
    end

    context "when a password is set" do
      let(:password) { "test.pass" }

      context "and the menu editing is restricted" do
        it "returns no issues" do
          issue = subject.validate(bootloader)
          expect(issue).to be_nil
        end
      end

      context "and the menu editing is not restricted" do
        let(:unrestricted) { true }

        it "returns an issue pointing that the bootloader menu editing" \
          " must be set as restricted" do
            issue = subject.validate(bootloader)
            expect(issue.message).to match(/Bootloader must be protected/)
            expect(issue.scope).to eq(:bootloader)
          end
      end
    end
  end
end
