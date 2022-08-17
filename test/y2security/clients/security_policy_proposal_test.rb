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

describe Y2Security::Clients::SecurityPolicyProposal do
  subject(:client) { described_class.new }

  let(:disa_stig_policy) do
    instance_double(
      Y2Security::SecurityPolicies::Policy,
      id:       :disa_stig,
      name:     "DISA STIG",
      packages: ["scap-security-guide"],
      enabled?: disa_stig_enabled?,
      validate: issues,
      enable:   nil,
      disable:  nil
    )
  end
  let(:issues) { [] }
  let(:disa_stig_enabled?) { false }

  before do
    allow(Y2Security::SecurityPolicies::Policy).to receive(:all)
      .and_return([disa_stig_policy])
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
    context "when the DISA STIG policy is enabled" do
      let(:disa_stig_enabled?) { true }

      xit "adds the packages needed by the policy to the packages proposal" do
        expect(Yast::PackagesProposal).to receive(:AddResolvables)
          .with("security", :package, disa_stig_policy.packages)
        subject.make_proposal({})
      end

      context "and the policy validation fails" do
        let(:issues) { [Y2Security::SecurityPolicies::Issue.new("Issue #1")] }

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

        it "includes the issues in the preformatted proposal" do
          expect(subject.make_proposal({})).to include(
            "preformatted_proposal" => /Issue #1/
          )
        end
      end

      it "includes a link to disable the policy" do
        expect(subject.make_proposal({})).to include(
          "preformatted_proposal" => %r{<a href=.*>disable</a>}
        )
      end
    end

    context "when the STIG policy is not enabled" do
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

      it "does not run the STIG validation" do
        expect(disa_stig_policy).to_not receive(:validate)
        subject.make_proposal({})
      end
    end
  end

  describe "#ask_user" do
    context "when the user asks to enable STIG" do
      it "disables the policy" do
        expect(disa_stig_policy).to receive(:enable)
        subject.ask_user(
          "chosen_id" => "security-policy--enable:#{disa_stig_policy.id}"
        )
      end

      it "returns :again as workflow result" do
        result = subject.ask_user(
          "chosen_id" => "security-policy--enable:#{disa_stig_policy.id}"
        )
        expect(result).to eq("workflow_result" => :again)
      end
    end

    context "when the user asks to disable STIG" do
      it "disables the policy" do
        expect(disa_stig_policy).to receive(:disable)
        subject.ask_user(
          "chosen_id" => "security-policy--disable:#{disa_stig_policy.id}"
        )
      end

      it "returns :again as workflow result" do
        result = subject.ask_user(
          "chosen_id" => "security-policy--disable:#{disa_stig_policy.id}"
        )
        expect(result).to eq("workflow_result" => :again)
      end
    end

    context "when the user asks to fix an issue" do
      let(:issue) do
        Y2Security::SecurityPolicies::Issue.new("The firewall is disabled", action)
      end
      let(:issues) { [issue] }
      let(:disa_stig_enabled?) { true }
      let(:action) do
        Y2Security::SecurityPolicies::Action.new("enable the firewall") do
          puts "enabling the firewall..."
        end
      end

      before { subject.make_proposal({}) }

      it "fixes the issue" do
        expect(issue).to receive(:fix)
        subject.ask_user(
          "chosen_id" => "security-policy--fix:#{issue.id}"
        )
      end
    end
  end
end
