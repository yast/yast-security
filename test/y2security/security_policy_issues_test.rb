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
require "y2security/security_policy_issues"
require "y2issues"

describe Y2Security::SecurityPolicyIssues do
  subject { described_class.new }

  describe "#update_scope" do
    let(:old_network_issue) do
      Y2Issues::Issue.new("issue 1", location: "proposal:network")
    end
    let(:new_network_issue) do
      Y2Issues::Issue.new("issue 2", location: "proposal:network")
    end
    let(:storage_issue) do
      Y2Issues::Issue.new("issue 3", location: "proposal:storage")
    end

    subject { described_class.new([old_network_issue, storage_issue]) }

    it "updates the issues in the given scope" do
      subject.update([new_network_issue])
      expect(subject.to_a).to eq([storage_issue, new_network_issue])
    end
  end
end
