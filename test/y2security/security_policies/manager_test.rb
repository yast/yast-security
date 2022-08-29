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
require "y2security/security_policies/manager"
require "y2security/security_policies/disa_stig_policy"

describe Y2Security::SecurityPolicies::Manager do
  # Always start with a new instance to make testing easier
  subject { described_class.send(:new) }

  before do
    allow(ENV).to receive(:[]) do |key|
      env[key]
    end

    allow(ENV).to receive(:keys).and_return env.keys
  end

  let(:env) { {} }

  let(:disa_stig_policy) { Y2Security::SecurityPolicies::DisaStigPolicy.new }

  describe ".new" do
    context "when YAST_SECURITY_POLICIES does not contain a policy" do
      let(:env) { { "YAST_SECURITY_POLICIES" => "" } }

      it "does not enable a policy" do
        expect(subject.enabled_policies).to be_empty
      end
    end

    context "when YAST_SECURITY_POLICIES contains an unknown policy" do
      let(:env) { { "YAST_SECURITY_POLICIES" => "DisaStig" } }

      it "does not enable a policy" do
        expect(subject.enabled_policies).to be_empty
      end
    end

    context "when YAST_SECURITY_POLICIES contains a known policy" do
      let(:env) { { "YAST_SECURITY_POLICIES" => "foo,Disa_Stig" } }

      it "enables the policy" do
        expect(subject.enabled_policies).to contain_exactly(disa_stig_policy)
      end
    end
  end

  describe "#policies" do
    it "returns all the known policies" do
      expect(subject.policies).to contain_exactly(disa_stig_policy)
    end
  end

  describe "#find_policy" do
    context "if there is a policy with the given id" do
      let(:id) { :disa_stig }

      it "returns the policy" do
        expect(subject.find_policy(id)).to eq(disa_stig_policy)
      end
    end

    context "if there is no policy with the given id" do
      let(:id) { :unknown }

      it "returns nil" do
        expect(subject.find_policy(id)).to be_nil
      end
    end
  end

  describe "#enable_policy" do
    context "if the given policy is unknown" do
      let(:policy) { Y2Security::SecurityPolicies::Policy.new(:unknown, "Unknown") }

      it "does not enable the policy" do
        subject.enable_policy(policy)

        expect(subject.enabled_policies).to_not include(policy)
      end
    end

    context "if the given policy is known" do
      let(:policy) { disa_stig_policy }

      it "enables the policy" do
        subject.enable_policy(policy)

        expect(subject.enabled_policies).to include(policy)
      end
    end
  end

  describe "#disable_policy" do
    before do
      subject.enable_policy(disa_stig_policy)
    end

    it "disables the given policy" do
      subject.disable_policy(disa_stig_policy)

      expect(subject.enabled_policies).to_not include(disa_stig_policy)
    end
  end

  describe "#enabled_policy?" do
    context "if the given policy is enabled" do
      before do
        subject.enable_policy(disa_stig_policy)
      end

      it "returns true" do
        expect(subject.enabled_policy?(disa_stig_policy)).to eq(true)
      end
    end

    context "if the given policy is not enabled" do
      before do
        subject.disable_policy(disa_stig_policy)
      end

      it "returns false" do
        expect(subject.enabled_policy?(disa_stig_policy)).to eq(false)
      end
    end
  end

  describe "#issues" do
    context "if there is no enabled policies" do
      before do
        subject.disable_policy(disa_stig_policy)
      end

      it "returns an empty collection" do
        expect(subject.issues.all).to be_empty
      end
    end

    context "if there are enabled policies" do
      before do
        subject.enable_policy(disa_stig_policy)

        allow(disa_stig_policy).to receive(:validate).and_return(issues)
      end

      let(:issues) { [Y2Security::SecurityPolicies::Issue.new("test")] }

      it "returns a collection with the issues of each policy" do
        expect(subject.issues.by_policy(disa_stig_policy)).to contain_exactly(*issues)
      end

      context "and the issues are requested for a scope" do
        before do
          subject.enable_policy(disa_stig_policy)

          allow(disa_stig_policy).to receive(:validate).with(storage_scope)
            .and_return(storage_issues)
          allow(disa_stig_policy).to receive(:validate).with(network_scope)
            .and_return(network_issues)
        end

        let(:storage_scope) { instance_double(Y2Security::SecurityPolicies::Scopes::Storage) }
        let(:network_scope) { instance_double(Y2Security::SecurityPolicies::Scopes::Network) }

        let(:storage_issues) { [Y2Security::SecurityPolicies::Issue.new("storage issue")] }
        let(:network_issues) { [Y2Security::SecurityPolicies::Issue.new("network issue")] }

        it "only returns the issues for the requested scope" do
          expect(subject.issues(storage_scope).by_policy(disa_stig_policy))
            .to contain_exactly(*storage_issues)

          expect(subject.issues(network_scope).by_policy(disa_stig_policy))
            .to contain_exactly(*network_issues)
        end
      end
    end
  end
end
