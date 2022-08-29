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

require_relative "../../../test_helper"
require "y2security/security_policies/scopes/bootloader"

describe Y2Security::SecurityPolicies::Scopes::Bootloader do
  describe "#new" do
    context "if a booloader object is given" do
      let(:grub2) { Bootloader::BootloaderFactory.bootloader_by_name("grub2") }

      it "creates the scope with the given bootloader" do
        scope = described_class.new(bootloader: grub2)

        expect(scope.bootloader).to eq(grub2)
      end
    end

    context "if no bootloader object is given" do
      before do
        allow(Bootloader::BootloaderFactory).to receive(:current).and_return(grub2_efi)
      end

      let(:grub2_efi) { Bootloader::BootloaderFactory.bootloader_by_name("grub2-efi") }

      it "creates the scope with the current bootloader" do
        scope = described_class.new

        expect(scope.bootloader).to eq(grub2_efi)
      end
    end
  end
end
