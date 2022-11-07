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
require "y2security/security_policies/policy"

shared_examples "Y2Security::SecurityPolicies::Policy" do
  class TestRule < Y2Security::SecurityPolicies::Rule
    def initialize(name, scope)
      super(name, description: "Test rule #{name}", scope: scope)
    end
  end

  describe "#failing_rules" do
    before do
      allow(subject).to receive(:rules).and_return(rules)
    end

    let(:rules) { [rule1, rule2, rule3, rule4] }

    let(:rule1) { TestRule.new("test1", :storage) }
    let(:rule2) { TestRule.new("test2", :storage) }
    let(:rule3) { TestRule.new("test3", :network) }
    let(:rule4) { TestRule.new("test4", :network) }

    let(:target_config) { instance_double(Y2Security::SecurityPolicies::TargetConfig) }

    context "when all rules pass" do
      before do
        allow(rule1).to receive(:pass?).and_return(true)
        allow(rule2).to receive(:pass?).and_return(true)
        allow(rule3).to receive(:pass?).and_return(true)
        allow(rule4).to receive(:pass?).and_return(true)
      end

      it "returns an empty array" do
        expect(subject.failing_rules(target_config)).to eq([])
      end
    end

    context "when some rules fail" do
      before do
        allow(rule1).to receive(:pass?).and_return(false)
        allow(rule2).to receive(:pass?).and_return(true)
        allow(rule3).to receive(:pass?).and_return(false)
        allow(rule4).to receive(:pass?).and_return(false)
      end

      it "includes the failing rules from all scopes by default" do
        rule4.disable

        expect(subject.failing_rules(target_config)).to contain_exactly(rule1, rule3)
      end

      it "includes the disabled failing rules if requested" do
        rule4.disable

        expect(subject.failing_rules(target_config, include_disabled: true))
          .to contain_exactly(rule1, rule3, rule4)
      end

      it "only includes the failing rules from a scope if requested" do
        expect(subject.failing_rules(target_config, scope: :storage)).to contain_exactly(rule1)
      end
    end
  end
end
