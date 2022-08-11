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
require "y2security/security_policy_validator"
require "y2security/security_policy"
require "y2security/disa_stig_validator"

describe Y2Security::SecurityPolicyValidator do
  let(:policy) { Y2Security::SecurityPolicy.find(:disa_stig) }

  describe ".for" do
    it "returns the validator for the given policy" do
      validator = described_class.for(policy)
      expect(validator).to be_a(Y2Security::DisaStigValidator)
    end
  end
end
