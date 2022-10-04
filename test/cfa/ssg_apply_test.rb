#!/usr/bin/env rspec

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

require_relative "../test_helper"
require "cfa/ssg_apply"

describe CFA::SsgApply do
  subject(:file) do
    described_class.new(file_handler: file_handler, file_path: file_path)
  end

  let(:file_handler) { Yast::TargetFile }

  let(:file_path) { File.join(DATA_PATH, "system/etc/ssg-apply/default.conf") }

  before do
    allow(file_handler).to receive(:write)
  end

  describe ".load" do
    context "when the file exists" do
      it "reads the file content" do
        file = described_class.load(file_path: file_path)
        expect(file).to be_a(described_class)
        expect(file.profile).to eq("stig")
      end
    end

    context "when the file does not exist" do
      let(:file_path) do
        File.join(DATA_PATH, "system/etc/ssg-apply/another.conf")
      end

      it "returns an empty file" do
        file = described_class.load(file_path: file_path)
        expect(file).to be_empty
      end
    end
  end

  describe "#save" do
    before do
      file.profile = profile
      file.remediate = remediate
    end

    let(:profile) { "disa_stig" }
    let(:remediate) { "yes" }

    it "writes the profile" do
      expect(file_handler).to receive(:write).with(anything, /profile = disa_stig/)

      file.save
    end

    it "writes the remediate value" do
      expect(file_handler).to receive(:write).with(anything, /remediate = yes/)

      file.save
    end

    context "when the profile is empty" do
      let(:profile) { "" }

      it "removes the profile key" do
        expect(file_handler).to receive(:write) do |_, content|
          expect(content).to_not include("profile")
        end

        file.save
      end
    end

    context "when the remediate is empty" do
      let(:remediate) { "" }

      it "removes the remediate key" do
        expect(file_handler).to receive(:write) do |_, content|
          expect(content).to_not include("remediate")
        end

        file.save
      end
    end
  end

  describe "#profile" do
    it "returns the profile value" do
      file.load
      expect(file.profile).to eq("stig")
    end
  end
end
