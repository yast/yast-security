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
require "y2security/security_policies/unknown_rule"
require "y2storage/devicegraph"
require "bootloader/main_dialog"

class DummyPolicy < Y2Security::SecurityPolicies::Policy
  def initialize
    textdomain "security"
    super(:dummy, _("Dummy policy"))
  end

  def rules
    @rules ||= [DummyRule.new]
  end
end

class DummyRule < Y2Security::SecurityPolicies::Rule
  def initialize
    textdomain "security"
    super("dummy_rule",
      identifiers: ["CCE-12345-67"],
      references:  ["SLES-15-000000"],
      description: _("Dummy rule"),
      scope:       :network)
  end
end

describe Y2Security::Clients::SecurityPolicyProposal do
  subject(:client) { described_class.new }

  let(:policies_manager) { Y2Security::SecurityPolicies::Manager.new }
  let(:policy) { DummyPolicy.new }
  let(:target_config) { instance_double(Y2Security::SecurityPolicies::TargetConfig) }

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
        "rich_text_title" => /Security Policies/,
        "menu_title"      => /Security Policies/
      )
    end
  end

  describe "#make_proposal" do
    context "when a policy is enabled" do
      before do
        policies_manager.enabled_policy = policy
      end

      it "includes a link to disable the policy" do
        expect(subject.make_proposal({})).to include(
          "preformatted_proposal" => %r{<a href=.*>disable</a>}
        )
      end

      context "and some rules are failing" do
        before do
          allow(rule).to receive(:pass?).and_return(false)
        end

        let(:rule) { policy.rules.first }

        it "includes a general warning message" do
          expect(subject.make_proposal({})).to include(
            "warning" => /does not comply/
          )
        end

        it "returns :error as warning_level" do
          expect(subject.make_proposal({})).to include(
            "warning_level" => :error
          )
        end

        it "includes a failing rules section" do
          expect(subject.make_proposal({})).to include(
            "preformatted_proposal" => /and are failing:.*Dummy rule/
          )
        end

        it "does not include a link to disable the rule" do
          expect(subject.make_proposal({})).to_not include(
            "preformatted_proposal" => %r{<a href=.*>disable rule</a>}
          )
        end

        context "and the failing rule is fixable" do
          before do
            allow(rule).to receive(:fixable?).and_return(true)
            allow(rule).to receive(:scope).and_return(:storage)
          end

          it "includes a link to fix the rule" do
            expect(subject.make_proposal({})).to include(
              "preformatted_proposal" => %r{<a href=.*>fix rule</a>}
            )
          end
        end

        context "and the failing rule is not fixable" do
          before do
            allow(rule).to receive(:fixable?).and_return(false)
          end

          context "and the scope is storage" do
            before do
              allow(rule).to receive(:scope).and_return(:storage)
            end

            it "includes a link to modify the storage settings" do
              expect(subject.make_proposal({})).to include(
                "preformatted_proposal" => %r{<a href=.*storage:\">modify settings</a>}
              )
            end
          end

          context "and the scope is bootloader" do
            before do
              allow(rule).to receive(:scope).and_return(:bootloader)
            end

            it "includes a link to modify the bootloader settings" do
              expect(subject.make_proposal({})).to include(
                "preformatted_proposal" => %r{<a href=.*bootloader:\">modify settings</a>}
              )
            end
          end
        end
      end

      context "and some rules are disabled" do
        before do
          allow(rule).to receive(:pass?).and_return(false)
          allow(rule).to receive(:enabled?).and_return(false)
          policy.rules << Y2Security::SecurityPolicies::UnknownRule.new("Unknown")
        end

        let(:rule) { policy.rules.first }

        it "includes a failing rules section" do
          expect(subject.make_proposal({})).to include(
            "preformatted_proposal" => /rules are disabled:.*Dummy rule/
          )
        end

        it "does not include a link to enable the rule" do
          expect(subject.make_proposal({})).to_not include(
            "preformatted_proposal" => %r{<a href=.*>enable rule</a>}
          )
        end

        context "and there are unknown rules" do
          before do
            policy.rules << Y2Security::SecurityPolicies::UnknownRule.new("unknown")
          end

          it "does not include the unknown rules" do
            expect(subject.make_proposal({})).to include(
              "preformatted_proposal" => /rules are disabled:.*Dummy rule/
            )

            expect(subject.make_proposal({})).to_not include(
              "preformatted_proposal" => /rules are disabled:.*unknown/
            )
          end
        end

        context "and the rule is fixable" do
          before do
            allow(rule).to receive(:fixable?).and_return(true)
          end

          it "does not include a link to fix the rule" do
            expect(subject.make_proposal({})).to_not include(
              "preformatted_proposal" => %r{<a href=.*>fix rule</a>}
            )
          end
        end

        context "and the rule is not fixable" do
          before do
            allow(rule).to receive(:fixable?).and_return(false)
            allow(rule).to receive(:scope).and_return(:storage)
          end

          it "does not include a link to modify the settings" do
            expect(subject.make_proposal({})).to_not include(
              "preformatted_proposal" => %r{<a href=.*>modify settings</a>}
            )
          end
        end
      end
    end

    context "when the policy is not enabled" do
      before do
        policies_manager.enabled_policy = nil
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

      context "and some rules are disabled" do
        before do
          allow(rule).to receive(:pass?).and_return(false)
          allow(rule).to receive(:enabled?).and_return(false)
        end

        let(:rule) { policy.rules.first }

        it "does not include a failing rules section" do
          expect(subject.make_proposal({})).to_not include(
            "preformatted_proposal" => /rules are disabled:/
          )
        end
      end
    end
  end

  describe "#ask_user" do
    context "when the user asks to enable a policy" do
      before do
        policies_manager.enabled_policy = nil
      end

      it "enables the policy" do
        subject.ask_user(
          "chosen_id" => "security-policy--toggle-policy:#{policy.id}"
        )
        expect(policies_manager.enabled_policy).to eq(policy)
      end

      it "returns :again as workflow result" do
        result = subject.ask_user(
          "chosen_id" => "security-policy--toggle-policy:#{policy.id}"
        )
        expect(result).to eq("workflow_sequence" => :again)
      end
    end

    context "when the user asks to disable a policy" do
      before do
        policies_manager.enabled_policy = policy
      end

      it "disables the policy" do
        subject.ask_user(
          "chosen_id" => "security-policy--toggle-policy:#{policy.id}"
        )
        expect(policies_manager.enabled_policy).to be_nil
      end

      it "returns :again as workflow result" do
        result = subject.ask_user(
          "chosen_id" => "security-policy--toggle-policy:#{policy.id}"
        )
        expect(result).to eq("workflow_sequence" => :again)
      end
    end

    context "when the user asks to fix an rule" do
      let(:rule) { policy.rules.first }

      before do
        policies_manager.enabled_policy = policy
        allow(rule).to receive(:pass?).and_return(false)
      end

      it "fixes the rule" do
        expect(rule).to receive(:fix).with(target_config)
        subject.ask_user(
          "chosen_id" => "security-policy--fix-rule:#{rule.id}"
        )
      end

      it "returns :again as workflow result" do
        result = subject.ask_user(
          "chosen_id" => "security-policy--fix-rule:#{policy.id}"
        )
        expect(result).to eq("workflow_sequence" => :again)
      end
    end

    context "when the user asks to modify the storage settings" do
      let(:rule) { policy.rules.first }

      before do
        policies_manager.enabled_policy = policy
        allow(rule).to receive(:pass?).and_return(false)
        allow(rule).to receive(:scope).and_return(:storage)

        allow(Yast::Wizard).to receive(:OpenAcceptDialog)
        allow(Yast::Wizard).to receive(:CloseDialog)

        allow(Yast::WFM).to receive(:CallFunction).and_return(client_result)
      end

      let(:client_result) { :cancel }

      it "opens the storage client" do
        expect(Yast::WFM).to receive(:CallFunction).with("inst_disk_proposal", anything)

        subject.ask_user("chosen_id" => "security-policy--storage:")
      end

      it "returns the client result as workflow result" do
        result = subject.ask_user(
          "chosen_id" => "security-policy--storage:"
        )
        expect(result).to eq("workflow_sequence" => :cancel)
      end
    end

    context "when the user asks to modify the bootloader settings" do
      let(:rule) { policy.rules.first }

      before do
        policies_manager.enabled_policy = policy
        allow(rule).to receive(:pass?).and_return(false)
        allow(rule).to receive(:scope).and_return(:bootloader)

        allow_any_instance_of(::Bootloader::MainDialog)
          .to receive(:run_auto).and_return(dialog_result)

        Yast::Bootloader.proposed_cfg_changed = false
      end

      let(:dialog_result) { :cancel }

      it "opens the bootloader dialog" do
        expect_any_instance_of(::Bootloader::MainDialog).to receive(:run_auto)

        subject.ask_user("chosen_id" => "security-policy--bootloader:")
      end

      it "returns the dialog result as workflow result" do
        result = subject.ask_user(
          "chosen_id" => "security-policy--bootloader:"
        )
        expect(result).to eq("workflow_sequence" => :cancel)
      end

      context "when the dialog is accepted" do
        let(:dialog_result) { :next }

        it "sets bootloader config as modified" do
          subject.ask_user("chosen_id" => "security-policy--bootloader:")

          expect(Yast::Bootloader.proposed_cfg_changed).to eq(true)
        end
      end

      context "when the dialog is not accepted" do
        let(:dialog_result) { :abort }

        it "does not set bootloader config as modified" do
          subject.ask_user("chosen_id" => "security-policy--bootloader:")

          expect(Yast::Bootloader.proposed_cfg_changed).to eq(false)
        end
      end
    end
  end
end
