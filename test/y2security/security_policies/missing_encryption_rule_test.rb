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
require "y2security/security_policies/missing_encryption_rule"

describe Y2Security::SecurityPolicies::MissingEncryptionRule do
  describe "#id" do
    it "returns the rule ID" do
      expect(subject.id).to eq("SLES-15-010330")
    end
  end

  describe "#validare" do
    let(:devicegraph) { Y2Storage::StorageManager.instance.staging }

    context "when there are not-encrypted and mounted file systems" do
      before do
        fake_storage_scenario("plain.yml")
      end

      it "returns an issue for missing encryption" do
        issue = subject.validate(devicegraph)

        expect(issue.message).to match(/not encrypted: \/, swap/)
        expect(issue.scope).to eq(:storage)
      end

      it "the issue does not include /boot/efi" do
        issue = subject.validate(devicegraph)

        expect(issue.message).to_not include("efi")
      end
    end

    context "when all mounted file systems are encrypted" do
      before do
        fake_storage_scenario("gpt_encryption.yml")
      end

      it "does not return an issue for missing encryption" do
        issue = subject.validate(devicegraph)
        expect(issue).to be_nil
      end
    end
  end
end
