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
require "y2security/security_policies/unknown_rule"

describe Y2Security::SecurityPolicies::Manager do
  before do
    allow(ENV).to receive(:[]) do |key|
      env[key]
    end

    allow(ENV).to receive(:keys).and_return env.keys

    allow(Y2Security::SecurityPolicies::DisaStigPolicy)
      .to receive(:new).and_return(disa_stig_policy)
  end

  let(:env) { {} }

  let(:disa_stig_policy) { Y2Security::SecurityPolicies::DisaStigPolicy.new }
  let(:target_config) do
    instance_double(Y2Security::SecurityPolicies::TargetConfig)
  end

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
      let(:env) { { "YAST_SECURITY_POLICIES" => "foo,Stig" } }

      it "enables the policy" do
        expect(subject.enabled_policies).to contain_exactly(disa_stig_policy)
      end
    end
  end

  describe "#scap_action" do
    it "returns :scan by default" do
      expect(subject.scap_action).to eq(:scan)
    end

    it "returns the given action" do
      subject.scap_action = :remediate
      expect(subject.scap_action).to eq(:remediate)
    end
  end

  describe "#policies" do
    it "returns all the known policies" do
      expect(subject.policies).to contain_exactly(disa_stig_policy)
    end
  end

  describe "#find_policy" do
    context "if there is a policy with the given id" do
      let(:id) { :stig }

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
    before do
      allow(subject).to receive(:require).with("installation/services")
        .and_return(true)
    end

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

      it "adds the ssg-apply package" do
        subject.enable_policy(policy)

        expect(Yast::PackagesProposal.GetResolvables("security", :package))
          .to include("ssg-apply")
      end

      after do
        Yast::PackagesProposal.RemoveResolvables("security", :package, ["ssg-apply"])
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

    it "removes the ssg-apply package" do
      subject.disable_policy(disa_stig_policy)

      expect(Yast::PackagesProposal.GetResolvables("security", :package))
        .to_not include("ssg-apply")
    end

    context "if more than one policy is enabled" do
      let(:another_policy) do
        instance_double(Y2Security::SecurityPolicies::Policy)
      end

      before do
        subject.instance_variable_set(:@policies, [disa_stig_policy, another_policy])
        subject.enable_policy(another_policy)
      end

      it "does not remove the package" do
        subject.disable_policy(disa_stig_policy)

        expect(Yast::PackagesProposal.GetResolvables("security", :package))
          .to include("ssg-apply")
      end

      after do
        Yast::PackagesProposal.RemoveResolvables("security", :package, ["ssg-apply"])
      end
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

  describe "#failing_rules" do
    context "if there are no enabled policies" do
      before do
        subject.disable_policy(disa_stig_policy)
      end

      it "returns an empty array" do
        expect(subject.failing_rules(target_config)).to be_empty
      end
    end

    context "if there are enabled policies" do
      let(:rule) { instance_double(Y2Security::SecurityPolicies::Rule) }

      before do
        subject.enable_policy(disa_stig_policy)

        allow(disa_stig_policy).to receive(:failing_rules)
          .with(target_config, include_disabled: false, scope: nil).and_return([rule])
      end

      it "returns a hash where the keys are the policies and the values the failing rules" do
        expect(subject.failing_rules(target_config)).to eq(disa_stig_policy => [rule])
      end

      context "when a scope is given" do
        it "only includes the rules for the given scope" do
          expect(disa_stig_policy).to receive(:failing_rules)
            .with(target_config, include_disabled: false, scope: :bootloader).and_return([rule])
          expect(subject.failing_rules(target_config, scope: :bootloader))
            .to eq(disa_stig_policy => [rule])
        end
      end

      context "when disabled rules must be included" do
        it "includes disabled rules" do
          expect(disa_stig_policy).to receive(:failing_rules)
            .with(target_config, include_disabled: true, scope: nil).and_return([rule])
          expect(subject.failing_rules(target_config, include_disabled: true))
            .to eq(disa_stig_policy => [rule])
        end
      end
    end
  end

  describe "#write" do
    before do
      allow(disa_stig_policy).to receive(:rules).and_return(rules)
      allow(Y2Security::SecurityPolicies::TargetConfig).to receive(:new)
        .and_return(target_config)
      subject.scap_action = scap_action

      allow(Yast::WFM).to receive(:scr_root).and_return(scr_root)
      FileUtils.mkdir_p(File.join(scr_root, "etc", "ssg-apply"))
      FileUtils.cp(
        File.join(DATA_PATH, "system", "etc", "ssg-apply", "default.conf"),
        default_file_path
      )

      allow(rule1).to receive(:pass?).and_return(false)
      allow(rule2).to receive(:pass?).and_return(false)
    end

    let(:scr_root) { Dir.mktmpdir }
    let(:scap_action) { :none }
    let(:default_file_path) { File.join(scr_root, "etc", "ssg-apply", "default.conf") }
    let(:override_file_path) { File.join(scr_root, "etc", "ssg-apply", "override.conf") }
    let(:rule1) { Y2Security::SecurityPolicies::UnknownRule.new("rule1").tap(&:enable) }
    let(:rule2) { Y2Security::SecurityPolicies::UnknownRule.new("rule2").tap(&:enable) }
    let(:rule3) { Y2Security::SecurityPolicies::UnknownRule.new("rule3").tap(&:disable) }
    let(:target_config) { instance_double(Y2Security::SecurityPolicies::TargetConfig) }

    let(:rules) { [rule1, rule2, rule3] }
    let(:target_config) do
      instance_double(Y2Security::SecurityPolicies::TargetConfig)
    end

    context "when a security policy is enabled" do
      before do
        subject.enable_policy(disa_stig_policy)
        subject.failing_rules(target_config, scope: :unknown, include_disabled: true)
      end

      after do
        FileUtils.remove_entry(scr_root) if Dir.exist?(scr_root)
      end

      it "writes failing rules in security_policy_failed_rules" do
        subject.write
        content = File.read(
          File.join(scr_root, "var", "log", "YaST2", "security_policy_failed_rules")
        )
        expect(content).to eq("rule1\nrule2\n")
      end

      context "when neither checks or remedation are enabled" do
        let(:scap_action) { :none }

        it "does not write the configuration" do
          subject.write
          expect(File).to_not exist(override_file_path)
        end

        it "does not enable the service" do
          expect(Yast::Service).to_not receive(:enable)
          subject.write
        end
      end

      context "when checking the policy after installation is enabled" do
        let(:scap_action) { :scan }

        it "disables ssg-apply remediation" do
          subject.write
          apply_file = CFA::SsgApply.load
          expect(apply_file.remediate).to eq("no")
          expect(apply_file.profile).to eq("stig")
        end

        it "enables the service" do
          expect(Yast::Service).to receive(:enable).with("ssg-apply")
          subject.write
        end
      end

      context "when full remediation is enabled" do
        let(:scap_action) { :remediate }

        it "enables ssg-apply remediation" do
          subject.write
          apply_file = CFA::SsgApply.load
          expect(apply_file.remediate).to eq("yes")
          expect(apply_file.profile).to eq("stig")
        end

        it "enables the service" do
          expect(Yast::Service).to receive(:enable).with("ssg-apply")
          subject.write
        end
      end
    end

    context "when no security policy is enabled" do
      before do
        subject.disable_policy(disa_stig_policy)
      end

      it "does not write the ssg-apply config" do
        subject.write
        expect(File).to_not exist(override_file_path)
      end

      it "does not enable the service" do
        expect(Yast::Service).to_not receive(:enable)
        subject.write
      end
    end
  end
end
