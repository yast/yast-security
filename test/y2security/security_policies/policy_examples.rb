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
  describe "#==" do
    context "when the policies have different class" do
      class OtherPolicy < Y2Security::SecurityPolicies::Policy
        def initialize
          super(:other, "other")
        end
      end

      let(:other) { OtherPolicy.new }

      it "returns false" do
        expect(subject == other).to eq(false)
      end
    end

    context "when the policies have the same class and id" do
      let(:other) { subject.class.new }

      it "returns true" do
        expect(subject == other).to eq(true)
      end
    end
  end

  describe "#validate" do
    before do
      allow(Y2Security::SecurityPolicies::Scopes::Storage)
        .to receive(:new).and_return(storage_scope)

      allow(Y2Security::SecurityPolicies::Scopes::Bootloader)
        .to receive(:new).and_return(bootloader_scope)

      allow(Y2Security::SecurityPolicies::Scopes::Network)
        .to receive(:new).and_return(network_scope)

      allow(Y2Security::SecurityPolicies::Scopes::Firewall)
        .to receive(:new).and_return(firewall_scope)
    end

    let(:storage_scope) { instance_double(Y2Security::SecurityPolicies::Scopes::Storage) }
    let(:bootloader_scope) { instance_double(Y2Security::SecurityPolicies::Scopes::Bootloader) }
    let(:network_scope) { instance_double(Y2Security::SecurityPolicies::Scopes::Network) }
    let(:firewall_scope) { instance_double(Y2Security::SecurityPolicies::Scopes::Firewall) }

    context "when no scope is given" do
      it "checks all the scopes" do
        expect(subject).to receive(:issues_for).with(storage_scope)
        expect(subject).to receive(:issues_for).with(bootloader_scope)
        expect(subject).to receive(:issues_for).with(network_scope)
        expect(subject).to receive(:issues_for).with(firewall_scope)

        subject.validate
      end
    end

    context "when a scope is given" do
      it "only checks the given scope" do
        expect(subject).to_not receive(:issues_for).with(storage_scope)
        expect(subject).to receive(:issues_for).with(bootloader_scope)
        expect(subject).to_not receive(:issues_for).with(network_scope)
        expect(subject).to_not receive(:issues_for).with(firewall_scope)

        subject.validate(bootloader_scope)
      end
    end
  end
end
