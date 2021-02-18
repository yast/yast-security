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
require "cfa/selinux"

describe CFA::Selinux do
  subject(:selinux_config_file) do
    described_class.load(file_path: file_path, file_handler: file_handler)
  end

  let(:selinux_path) { "config" }
  let(:file_handler) { File }
  let(:file_path) { File.join(DATA_PATH, "system/etc/selinux/config") }

  describe ".load" do
    context "when file exist" do
      it "creates an own Augeas instance using simplevars lens" do
        expect(::CFA::AugeasParser).to receive(:new).with("simplevars.lns").and_call_original

        described_class.load(file_path: file_path, file_handler: file_handler)
      end

      it "loads the file content" do
        file = described_class.load(file_path: file_path, file_handler: file_handler)

        expect(file.loaded?).to eq(true)
      end
    end

    context "when file does not exist" do
      let(:file_path) { "/file/not/created/yet" }

      it "creates an own Augeas instance using simplevars lens" do
        expect(::CFA::AugeasParser).to receive(:new).with("simplevars.lns").and_call_original

        described_class.load(file_path: file_path, file_handler: file_handler)
      end

      it "does not load the file content" do
        file = described_class.load(file_path: file_path, file_handler: file_handler)

        expect(file.loaded?).to eq(false)
      end
    end
  end

  describe "#initialize" do
    it "creates an own Augeas instance using simplevars lens" do
      expect(::CFA::AugeasParser).to receive(:new).with("simplevars.lns").and_call_original

      described_class.new(file_handler: file_handler)
    end
  end

  describe "#selinux" do
    it "returns the SELINUX value" do
      expect(subject.selinux).to eq("enforcing")
    end
  end

  describe "#selinux=" do
    it "sets the SELINUX value" do
      expect { subject.selinux = "permissive" }
        .to change { subject.selinux }.from("enforcing").to("permissive")
    end
  end

  describe "#save" do
    let(:selinux_mode) { "enforcing" }

    before do
      allow(Yast::SCR).to receive(:Write)
      allow(file_handler).to receive(:read).with(file_path)
        .and_return("# Some comment\nSELINUX=permissive")
      subject.load
      subject.selinux = selinux_mode
    end

    it "writes changes to configuration file" do
      expect(file_handler).to receive(:write)
        .with(file_path, /.*SELINUX=#{selinux_mode}.*/)

      subject.save
    end
  end
end
