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

require "yast"

module Y2Security
  module SecurityPolicies
    class Rule
      include Yast::I18n

      # @return [String]
      attr_reader :id

      # @return [Symbol]
      attr_reader :scope

      # @param id [String] Rule ID (e.g., "SLES-15-010190")
      # @param scope [Symbol] Scope 
      def initialize(id, scope)
        textdomain "security"

        @id = id
        @scope = scope
        @enabled = true
      end

      def enable
        @enabled = true
      end

      def disable
        @enabled = false
      end

      def enabled?
        @enabled
      end

      def validate
        true
      end

      def action
        nil
      end
    end
  end
end
