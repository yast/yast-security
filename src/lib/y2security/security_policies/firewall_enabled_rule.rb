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

require "y2security/security_policies/rule"

module Y2Security
  module SecurityPolicies
    # Rule to verify that the firewall is enabled
    class FirewallEnabledRule < Rule
      def initialize
        textdomain "security"

        # TRANSLATORS: security policy rule
        description = _("Firewall must be enabled")

        super("service_firewalld_enabled",
          identifiers: ["CCE-85751-6"],
          references:  ["SLES-15-010220"],
          description: description,
          scope:       :security)
      end

      # @see Rule#pass?
      def pass?(target_config)
        !!target_config.security&.enable_firewall
      end

      # @see Rule#fixable?
      def fixable?
        true
      end

      # @see Rule#fix
      def fix(target_config)
        target_config.security.enable_firewall!
      end
    end
  end
end
