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
#

require_relative "../../test_helper"
require "y2security/clients/security_policy_proposal"
require "y2security/security_policies"
require "y2storage/devicegraph"

class DummyPolicy < Y2Security::SecurityPolicies::Policy
  def initialize
    textdomain "security"
    super(:dummy, _("Dummy policy"), [])
  end

  def rules
    @rules ||= [DummyRule.new]
  end
end

class DummyRule < Y2Security::SecurityPolicies::Rule
  def initialize
    textdomain "security"
    super("SLES-15-000000", _("Dummy rule"), :network)
  end
end

describe Y2Security::Clients::SecurityPolicyProposal do
  subject(:client) { described_class.new }

  let(:policies_manager) { Y2Security::SecurityPolicies::Manager.new }
  let(:policy) { DummyPolicy.new }
  let(:target_config) { instance_double(Y2Security::SecurityPolicies::TargetConfig )}

  before do
    allow(Y2Security::SecurityPolicies::Manager).to receive(:instance)
      .and_return(policies_manager)
    allow(policies_manager).to receive(:policies).and_return([policy])
    allow(Y2Security::SecurityPolicies::TargetConfig).to receive(:new)
      .and_return(target_config)
  end

  describe "#description" do
    it "returns a hash with the description" do
      expect(subject.description).to include(
        "rich_text_title" => /Security Policy/,
        "menu_title"      => /Security Policy/
      )
    end
  end

  describe "#make_proposal" do
    context "when a policy is enabled" do
      before do
        policies_manager.enable_policy(policy)
        rule = policy.rules.first
        allow(rule).to receive(:pass?).and_return(false)
      end

      xit "adds the packages needed by the policy to the packages proposal" do
        expect(Yast::PackagesProposal).to receive(:AddResolvables)
          .with("security", :package, disa_stig_policy.packages)
        subject.make_proposal({})
      end

      context "and the policy validation fails" do
        it "returns a warning message" do
          expect(subject.make_proposal({})).to include(
            "warning" => /does not comply/
          )
        end

        it "returns :block as warning_level" do
          expect(subject.make_proposal({})).to include(
            "warning_level" => :blocker
          )
        end

        it "includes the failing rules in the preformatted proposal" do
          expect(subject.make_proposal({})).to include(
            "preformatted_proposal" => /Dummy rule/
          )
        end
      end

      it "includes a link to disable the policy" do
        expect(subject.make_proposal({})).to include(
          "preformatted_proposal" => %r{<a href=.*>disable</a>}
        )
      end
    end

    context "when the policy is not enabled" do
      before do
        policies_manager.disable_policy(policy)
      end

      xit "removes the packages needed by the policy from the packages proposal" do
        expect(Yast::PackagesProposal).to receive(:RemoveResolvables)
          .with("security", :package, disa_stig_policy.packages)
        subject.make_proposal({})
      end

      it "includes a link to enable the policy" do
        expect(subject.make_proposal({})).to include(
          "preformatted_proposal" => %r{<a href=.*>enable</a>}
        )
      end

      it "does not run check the policy" do
        expect(policy).to_not receive(:failing_rules)
        subject.make_proposal({})
      end
    end
  end

  describe "#ask_user" do
    context "when the user asks to enable a policy" do
      before do
        policies_manager.disable_policy(policy)
      end

      it "enables the policy" do
        subject.ask_user(
          "chosen_id" => "security-policy--toggle-policy:#{policy.id}"
        )
        expect(policies_manager.enabled_policy?(policy)).to eq(true)
      end

      it "returns :again as workflow result" do
        result = subject.ask_user(
          "chosen_id" => "security-policy--toggle-policy:#{policy}"
        )
        expect(result).to eq("workflow_result" => :again)
      end
    end

    context "when the user asks to disable a policy" do
      before do
        policies_manager.enable_policy(policy)
      end

      it "disables the policy" do
        subject.ask_user(
          "chosen_id" => "security-policy--toggle-policy:#{policy.id}"
        )
        expect(policies_manager.enabled_policies).to_not include(policy)
      end

      it "returns :again as workflow result" do
        result = subject.ask_user(
          "chosen_id" => "security-policy--toggle-policy:#{policy.id}"
        )
        expect(result).to eq("workflow_result" => :again)
      end
    end

    context "when the user asks to fix an rule" do
      let(:rule) { policy.rules.first }

      before do
        policies_manager.enable_policy(policy)
        allow(rule).to receive(:pass?).and_return(false)
      end

      it "fixes the rule" do
        subject.make_proposal({})
        expect(rule).to receive(:fix).with(target_config)
        subject.ask_user(
          "chosen_id" => "security-policy--fix-rule:#{rule.id}"
        )
      end
    end

    xcontext "when the user asks to open the partitioning client" do
      before do
        policies_manager.enable_policy(disa_stig_policy)

        allow(disa_stig_policy).to receive(:validate).and_return(issues)

        allow(Yast::Wizard).to receive(:OpenAcceptDialog)
        allow(Yast::Wizard).to receive(:CloseDialog)
      end

      let(:scope) { Y2Security::SecurityPolicies::Scopes::Storage.new(devicegraph: devicegraph) }

      let(:devicegraph) { instance_double(Y2Storage::Devicegraph) }

      it "opens the partitioning" do
        expect(Yast::WFM).to receive(:CallFunction).with("inst_disk_proposal", anything)

        subject.make_proposal({})
        subject.ask_user("chosen_id" => "security-policy--storage:0")
      end
    end
  end
end
