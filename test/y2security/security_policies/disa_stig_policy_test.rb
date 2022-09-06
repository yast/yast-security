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
require_relative "./policy_examples"
require "y2security/security_policies/disa_stig_policy"

describe Y2Security::SecurityPolicies::DisaStigPolicy do
  include_examples "Y2Security::SecurityPolicies::Policy"

  describe "#validate" do
    context "when validating the storage scope" do
      let(:scope) { Y2Security::SecurityPolicies::Scopes::Storage.new(devicegraph: devicegraph) }

  end

  context "when validating the firewall scope" do
    let(:scope) do
      Y2Security::SecurityPolicies::Scopes::Firewall.new(security_settings: security_settings)
    end

    let(:security_settings) do
      instance_double("Installation::SecuritySettings", enable_firewall: enabled)
    end

    let(:enabled) { true }

    context "and the firewall is enabled" do
      it "returns no issues" do
        issues = subject.validate(scope)
        expect(issues).to be_empty
      end
    end

    context "and the firewall is not enabled " do
      let(:enabled) { false }

      it "returns an issue pointing that the firewall is not enabled" do
        issues = subject.validate(scope)
        expect(issues.size).to eq(1)

        issue = issues.first

        expect(issue.message).to include("Firewall is not enabled")
        expect(issue.scope).to eq(scope)
      end
    end
  end

  context "when validating the bootloader scope" do
    let(:scope) { Y2Security::SecurityPolicies::Scopes::Bootloader.new(bootloader: bootloader) }

    let(:bootloader) { Bootloader::NoneBootloader.new }

    context "and no Grub based bootloader is selected" do
      it "returns no issues" do
        issues = subject.validate(scope)
        expect(issues).to be_empty
      end
    end

    context "and a Grub based bootloader is selected" do
      let(:bootloader) { Bootloader::Grub2.new }
      let(:password) { nil }
      let(:unrestricted) { false }

      before do
        if password
          bootloader.password.used = true
          bootloader.password.unrestricted = unrestricted
        end
      end

      context "when a password is not set" do
        it "returns an issue pointing that the bootloader password must be set" do
          issues = subject.validate(scope)
          expect(issues.size).to eq(2)

          issue = issues.first
          expect(issue.message).to include("Bootloader password must be set")
          expect(issue.scope).to eq(scope)
        end
      end

      context "when a password is set" do
        let(:password) { "test.pass" }

        context "and the menu editing is restricted" do
          it "returns no issues" do
            issues = subject.validate(scope)
            expect(issues).to be_empty
          end
        end

        context "and the menu editing is not restricted" do
          let(:unrestricted) { true }

          it "returns an issue pointing that the bootloader menu editing" \
             " must be set as restricted" do
            issues = subject.validate(scope)
            expect(issues.size).to eq(1)

            issue = issues.first

            expect(issue.message).to include("Bootloader menu editing must be set as restricted")
            expect(issue.scope).to eq(scope)
          end
        end
      end
    end
  end
end
