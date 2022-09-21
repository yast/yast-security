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
    described_class.new(file_path: file_path)
  end

  let(:file_path) { File.join(DATA_PATH, "system/etc/ssg-apply/default.conf") }

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

  describe "#profile" do
    it "returns the profile value" do
      file.load
      expect(file.profile).to eq("stig")
    end
  end

  describe "#disabled_rules" do
    context "when a 'disabled_rules' list is specified" do
      let(:file_path) { File.join(DATA_PATH, "system/etc/ssg-apply/override.conf") }

      it "returns an array containing the disabled rules" do
        file.load
        expect(file.disabled_rules).to eq(["SLES-15-040200", "SLES-15-010200"])
      end
    end

    context "when no 'disabled_rules' list is specified" do
      it "returns an empty array" do
        expect(file.disabled_rules).to eq([])
      end
    end
  end

  describe "#disabled_rules=" do
    it "sets the 'disabled-rules' key to a comma separated list" do
      expect(file).to receive(:generic_set)
        .with("disabled-rules", "SLES-15-040200,SLES-15-010200")
      file.disabled_rules = ["SLES-15-040200", "SLES-15-010200"]
    end
  end
end
