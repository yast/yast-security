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

require_relative "../../../test_helper"
require "y2security/security_policies/scopes/firewall"

# The package yast2-installation is needed to get the security settings, but yast2-installation
# is not added as dependency to avoid cyclic dependencies. These tests are mocking
# Installation::SecuritySettings, covering both cases when the package is available and when it is
# missing.

# Namespace typically used for classes coming from yast2-installation
module Installation; end

describe Y2Security::SecurityPolicies::Scopes::Firewall do
  # Mocks require of security settings class
  before do
    allow_any_instance_of(described_class).to receive(:require).and_call_original
    allow_any_instance_of(described_class).to receive(:require)
      .with("installation/security_settings") do
      raise LoadError, "cannot load such file" unless yast2_installation_available

      define_security_settings_class
    end
  end

  after do
    Installation.send(:remove_const, "SecuritySettings") if yast2_installation_available
  end

  # Defines a fake class to mock the security settings from yast2-installation
  def define_security_settings_class
    c = Class.new do |k|
      def k.instance
        @instance ||= new
      end
    end

    Installation.const_set("SecuritySettings", c)
  end

  let(:yast2_installation_available) { true }

  describe "#new" do
    context "if a security settings object is given" do
      before do
        define_security_settings_class
      end

      let(:security_settings) { Installation::SecuritySettings.new }

      it "creates the scope with the given security settings" do
        scope = described_class.new(security_settings: security_settings)

        expect(scope.security_settings).to eq(security_settings)
      end
    end

    context "if no security settings object is given" do
      context "and installation/security_settings can be required" do
        let(:yast2_installation_available) { true }

        it "creates the scope with the current security settings" do
          scope = described_class.new

          expect(scope.security_settings).to eq(Installation::SecuritySettings.instance)
        end
      end

      context "and installation/security_settings is missing" do
        let(:yast2_installation_available) { false }

        it "creates the scope without security settings" do
          scope = described_class.new

          expect(scope.security_settings).to be_nil
        end
      end
    end
  end
end
