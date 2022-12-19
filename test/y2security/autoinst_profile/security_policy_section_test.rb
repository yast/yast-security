#!/usr/bin/env rspec
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
require "y2security/autoinst_profile/security_policy_section"

describe Y2Security::AutoinstProfile::SecurityPolicySection do
  describe ".new_from_hashes" do
    let(:profile) do
      { "action" => "remediate", "policy" => "stig" }
    end

    it "sets the SCAP action and the list of enabled policies" do
      section = described_class.new_from_hashes(profile)
      expect(section.action).to eq("remediate")
      expect(section.policy).to eq("stig")
    end

    context "an empty profile" do
      it "returns an empty section" do
        section = described_class.new_from_hashes({})
        expect(section.action).to be_nil
        expect(section.policy).to be_nil
      end
    end
  end

  describe ".new_from_system" do
    let(:on_installation?) { true }
    let(:service_enabled?) { true }

    let(:manager) do
      instance_double(
        Y2Security::SecurityPolicies::Manager, service_enabled?: service_enabled?,
        on_installation?: on_installation?
      )
    end

    let(:file) { instance_double(CFA::SsgApply, profile: "stig") }

    before do
      allow(Y2Security::SecurityPolicies::Manager).to receive(:instance)
        .and_return(manager)
      allow(CFA::SsgApply).to receive(:load).and_return(file)
    end

    context "when the security policies did not run at installation time" do
      let(:on_installation?) { false }

      it "returns an empty section" do
        section = described_class.new_from_system
        expect(section.to_hashes).to be_empty
      end
    end

    context "when the ssg-apply service is disabled" do
      let(:service_enabled?) { false }

      it "returns a section with action set to 'none'" do
        section = described_class.new_from_system
        expect(section.action).to eq("none")
      end
    end

    context "when the remediate option is set to 'yes'" do
      let(:file) do
        instance_double(CFA::SsgApply, profile: "stig", remediate: "yes")
      end

      it "returns a section with action set to 'remediate'" do
        section = described_class.new_from_system
        expect(section.action).to eq("remediate")
      end
    end

    context "when the remediate option is set to 'no'" do
      let(:file) do
        instance_double(CFA::SsgApply, profile: "stig", remediate: "no")
      end

      it "returns a section with action set to 'scan'" do
        section = described_class.new_from_system
        expect(section.action).to eq("scan")
      end
    end
  end
end
