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
require "y2security/security_policies/validator"
require "y2security/security_policies/disa_stig_validator"
require "y2security/security_policies/policy"

describe Y2Security::SecurityPolicies::Validator do
  let(:policy) { Y2Security::SecurityPolicies::Policy.find(:disa_stig) }

  describe ".for" do
    it "returns the validator for the given policy" do
      validator = described_class.for(policy)
      expect(validator).to be_a(Y2Security::SecurityPolicies::DisaStigValidator)
    end
  end
end
