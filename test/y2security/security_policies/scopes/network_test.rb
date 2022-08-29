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
require "y2security/security_policies/scopes/network"
require "y2network/config"

describe Y2Security::SecurityPolicies::Scopes::Network do
  describe "#new" do
    context "if a network config object is given" do
      let(:config) { instance_double(Y2Network::Config) }

      it "creates the scope with the given network config" do
        scope = described_class.new(config: config)

        expect(scope.config).to eq(config)
      end
    end

    context "if no network config object is given" do
      before do
        allow(Yast::Lan).to receive(:yast_config).and_return(config)
      end

      let(:config) { instance_double(Y2Network::Config) }

      it "creates the scope with the current YaST config" do
        scope = described_class.new

        expect(scope.config).to eq(config)
      end
    end
  end
end
