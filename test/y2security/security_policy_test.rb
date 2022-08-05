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
require "y2security/security_policy"
require "y2issues/issue"

describe Y2Security::SecurityPolicy do
  subject { described_class.new(:dummy, "Dummy Policy") }

  describe ".all" do
    it "returns the list of known policies" do
      policies = described_class.all
      expect(policies.map(&:id)).to eq([:stig])
    end
  end

  describe "#validate" do
    let(:validator) do
      instance_double(Y2Security::SecurityPolicyValidator)
    end
    let(:issue) { Y2Issues::Issue.new("networking issue") }
    let(:issues_list) { Y2Security::SecurityPolicyIssues.new([issue]) }

    before do
      allow(Y2Security::SecurityPolicyValidator).to receive(:for)
        .with(subject).and_return(validator)
    end

    it "registers the issues from the validation" do
      expect(validator).to receive(:issues).with(:network).and_return(issues_list)
      subject.validate(:network)
      expect(subject.issues.to_a).to eq([issue])
    end
  end
end
