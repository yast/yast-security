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
require "y2security/security_policies/issue"
require "y2security/security_policies/action"

describe Y2Security::SecurityPolicies::Issue do
  describe "#auto" do
    context "when the issue has an associated action" do
      let(:action) { instance_double(Y2Security::SecurityPolicies::Action) }
      subject { described_class.new("Some issue", action) }

      it "is an automatic issue" do
        expect(subject).to be_auto
      end
    end

    context "when the issue has no associated action" do
      subject { described_class.new("Some issue") }

      it "is not an automatic issue" do
        expect(subject).to_not be_auto
      end
    end
  end
end
