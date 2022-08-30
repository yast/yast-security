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
require "y2security/security_policies/policy"
require "y2security/security_policies/disa_stig_policy"

describe Y2Security::SecurityPolicies::IssuesCollection do
  let(:policy) { Y2Security::SecurityPolicies::DisaStigPolicy.new }

  describe "#update" do
    it "updates the list of issues of the given policy" do
      expect(subject.by_policy(policy)).to be_empty

      issues = [Y2Security::SecurityPolicies::Issue.new("test")]
      subject.update(policy, issues)

      expect(subject.by_policy(policy)).to eq(issues)
    end
  end

  describe "#by_policy" do
    context "if there is no issues for the given policy" do
      it "returns an empty list" do
        expect(subject.by_policy(policy)).to be_empty
      end
    end

    context "if there are issues for the given policy" do
      before do
        subject.update(policy, issues)
      end

      let(:issues) { [Y2Security::SecurityPolicies::Issue.new("test")] }

      it "returns the list of issues" do
        expect(subject.by_policy(policy)).to eq(issues)
      end
    end
  end

  describe "#all" do
    before do
      subject.update(policy1, issues1)
      subject.update(policy2, issues2)
    end

    let(:policy1) { Y2Security::SecurityPolicies::Policy.new(:test1, "Test1") }
    let(:policy2) { Y2Security::SecurityPolicies::Policy.new(:test2, "Test2") }
    let(:issues1) { [Y2Security::SecurityPolicies::Issue.new("issue1")] }
    let(:issues2) { [Y2Security::SecurityPolicies::Issue.new("issue2")] }

    it "returns all the issues from all the policies" do
      expect(subject.all).to contain_exactly(
        an_object_having_attributes(message: "issue1"),
        an_object_having_attributes(message: "issue2")
      )
    end
  end

  describe "#to_h" do
    before do
      subject.update(policy1, issues1)
      subject.update(policy2, issues2)
    end

    let(:policy1) { Y2Security::SecurityPolicies::Policy.new(:test1, "Test1") }
    let(:policy2) { Y2Security::SecurityPolicies::Policy.new(:test2, "Test2") }
    let(:issues1) { [Y2Security::SecurityPolicies::Issue.new("issue1")] }
    let(:issues2) { [Y2Security::SecurityPolicies::Issue.new("issue2")] }

    it "returns a hash with the policies as keys and the issues as values" do
      hash = subject.to_h

      expect(hash.keys).to contain_exactly(policy1, policy2)
      expect(hash[policy1]).to eq(issues1)
      expect(hash[policy2]).to eq(issues2)
    end
  end
end

describe Y2Security::SecurityPolicies::Issue do
  describe "#action?" do
    context "when the issue has an associated action" do
      let(:action) { instance_double(Y2Security::SecurityPolicies::Action) }

      subject { described_class.new("Some issue", action: action) }

      it "returns true" do
        expect(subject.action?).to eq(true)
      end
    end

    context "when the issue has no associated action" do
      subject { described_class.new("Some issue") }

      it "returns false" do
        expect(subject.action?).to eq(false)
      end
    end
  end

  describe "#scope?" do
    context "when the issue has an associated scope" do
      let(:scope) { instance_double(Y2Security::SecurityPolicies::Scopes::Storage) }

      subject { described_class.new("Some issue", scope: scope) }

      it "returns true" do
        expect(subject.scope?).to eq(true)
      end
    end

    context "when the issue has no associated scope" do
      subject { described_class.new("Some issue") }

      it "returns false" do
        expect(subject.scope?).to eq(false)
      end
    end
  end
end
