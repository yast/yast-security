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

describe Y2Security::SecurityPolicy do
  before { described_class.reset }
  subject { described_class.new(:dummy, "Dummy Policy") }

  describe ".all" do
    it "returns the list of known policies" do
      policies = described_class.all
      expect(policies.map(&:id)).to eq([:stig])
    end
  end

  describe ".enable" do
    let(:policy) { described_class.all.first }

    it "enables a security policy" do
      expect(described_class.enabled).to eq([])
      described_class.enable(policy)
      expect(described_class.enabled).to eq([policy])
    end
  end

  describe ".valid?" do
    let(:validator) { instance_double(Y2Security::SecurityPolicyValidator) }

    before do
      allow(Y2Security::SecurityPolicyValidator).to receive(:for).with(subject.id)
        .and_return(validator)
    end

    it "returns whether the validation passed according to the validator" do
      expect(validator).to receive(:valid?).and_return(true)
      expect(subject.valid?).to eq(true)
    end

    it "returns the errors from the validation" do
      expect(validator).to receive(:errors).and_return(["error1"])
      expect(subject.errors).to eq(["error1"])
    end
  end
end
