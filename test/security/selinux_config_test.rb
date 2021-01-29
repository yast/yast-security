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

  before do
    allow(Yast::Bootloader).to receive(:kernel_param).with(:common, "security")
      .and_return(security)
    allow(Yast::Bootloader).to receive(:kernel_param).with(:common, "selinux")
      .and_return(selinux)
    allow(Yast::Bootloader).to receive(:kernel_param).with(:common, "enforcing")
      .and_return(enforcing)
  end

  describe "#policy" do
    pending
  end

  describe "#policy=" do
    pending
  end

  describe "#running_policy=" do
    pending
  end
end
