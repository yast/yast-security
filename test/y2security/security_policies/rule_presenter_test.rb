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
require "y2security/security_policies/rule_presenter"
require "y2security/security_policies/rule"

describe Y2Security::SecurityPolicies::RulePresenter do
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

  subject(:client) { described_class.new(rule, toggle_link: toggle_link, fix_link: fix_link) }

  let(:rule) { DummyRule.new }

  let(:toggle_link) { nil }

  let(:fix_link) { nil }

  describe "#to_html" do
    it "includes the identifiers of the rule" do
      expect(subject.to_html).to include("CCE-12345-67")
    end

    it "includes the references of the rule" do
      expect(subject.to_html).to include("SLES-15-000000")
    end

    it "includes the description of the rule" do
      expect(subject.to_html).to include("Dummy rule")
    end

    context "when there is a link for toggling the rule" do
      let(:toggle_link) { "toggle-rule:1" }

      context "and the rule is enabled" do
        before do
          rule.enable
        end

        it "includes a hyperlink for disabling the rule" do
          expect(subject.to_html).to match(%r{<a href=.*>disable rule</a>})
        end
      end

      context "and the rule is disabled" do
        before do
          rule.disable
        end

        it "includes a hyperlink for enabling the rule" do
          expect(subject.to_html).to match(%r{<a href=.*>enable rule</a>})
        end
      end
    end

    context "when there is no link for toggling the rule" do
      let(:toggle_link) { nil }

      it "does not include a hyperlink for toggling the rule" do
        expect(subject.to_html).to_not match(%r{toggle-rule:1})
      end
    end

    context "when there is a link for fixing the rule" do
      let(:fix_link) { "fix-rule:1" }

      context "and the rule is fixable" do
        before do
          allow(rule).to receive(:fixable?).and_return(true)
        end

        context "and the rule is enabled" do
          before do
            rule.enable
          end

          it "includes a hyperlink for fixing the rule" do
            expect(subject.to_html).to match(%r{<a href=.*>fix rule</a>})
          end
        end

        context "and the rule is disabled" do
          before do
            rule.disable
          end

          it "does not include a hyperlink for fixing the rule" do
            expect(subject.to_html).to_not match(%r{<a href=.*>fix rule</a>})
          end
        end
      end

      context "and the rule is not fixable" do
        before do
          allow(rule).to receive(:fixable?).and_return(false)
        end

        context "and the rule is enabled" do
          before do
            rule.enable
          end

          it "includes a hyperlink for modifying the settings" do
            expect(subject.to_html).to match(%r{<a href=.*>modify settings</a>})
          end
        end

        context "and the rule is disabled" do
          before do
            rule.disable
          end

          it "does not include a hyperlink for fixing the rule" do
            expect(subject.to_html).to_not match(%r{<a href=.*>fix rule</a>})
          end

          it "does not include a hyperlink for modifying the settings" do
            expect(subject.to_html).to_not match(%r{<a href=.*>modify settings</a>})
          end
        end
      end
    end

    context "when there is no link for fixing the rule" do
      let(:fix_link) { nil }

      before do
        rule.enable
        allow(rule).to receive(:fixable?).and_return(true)
      end

      it "does not include a hyperlink for fixing the rule" do
        expect(subject.to_html).to_not match(%r{fix-rule:1})
      end
    end
  end
end
