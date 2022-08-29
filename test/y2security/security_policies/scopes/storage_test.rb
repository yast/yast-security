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
require "y2security/security_policies/scopes/storage"
require "y2storage/devicegraph"

describe Y2Security::SecurityPolicies::Scopes::Storage do
  describe "#new" do
    context "if a devicegraph object is given" do
      let(:devicegraph) { instance_double(Y2Storage::Devicegraph) }

      it "creates the scope with the given devicegraph" do
        scope = described_class.new(devicegraph: devicegraph)

        expect(scope.devicegraph).to eq(devicegraph)
      end
    end

    context "if no devicegraph object is given" do
      before do
        allow(Y2Storage::StorageManager.instance).to receive(:staging).and_return(staging)
      end

      let(:staging) { instance_double(Y2Storage::Devicegraph) }

      it "creates the scope with the staging devicegraph" do
        scope = described_class.new

        expect(scope.devicegraph).to eq(staging)
      end
    end
  end
end
