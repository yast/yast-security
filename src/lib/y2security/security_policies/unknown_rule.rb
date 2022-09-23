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
require "y2security/security_policies/rule"

module Y2Security
  module SecurityPolicies
    # Represents an unknown rule
    #
    # Unknown rules usually come from an AutoYaST profile. The profile allows disabling rules, but
    # some of the given rules could be unknown by YaST. Note that YaST is aware of only an small
    # subset of rules that should be fixed at installation time. For the rest of rules, an unknown
    # rule is added to the policy when importing the profile.
    class UnknownRule < Rule
      include Yast::I18n

      # @param name [String] Rule name
      def initialize(name)
        textdomain "security"

        super(name, description: _("Unknown rule"), scope: :unknown)
      end

      # Unknown rules are always considered as passing.
      def pass?(_target_config)
        true
      end

      # Unknown rules cannot be fixed
      def fixable?
        false
      end
    end
  end
end
