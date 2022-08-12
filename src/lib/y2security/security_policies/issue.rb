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

module Y2Security
  module SecurityPolicies
    class Issue
      attr_reader :id, :message, :action

      @@id = 0

      # @param message [String] Issue message
      # @param block [Proc] Code to remedy the issue
      #
      # TODO: add the issue code from the policy/profile?
      def initialize(message, action = nil)
        @@id += 1
        @id = @@id
        @message = message
        @action = action
      end

      def auto?
        !@action.nil?
      end

      def fix
        return nil unless auto?

        @action.run
      end
    end
  end
end
