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
require "y2security/security_policies/issue"
require "y2security/security_policies/action"
require "installation/security_settings"

module Y2Security
  module SecurityPolicies
    # Rule to verify that the firewall is enabled (SLES-15-010220).
    class FirewallEnabledRule < Rule
      def initialize
        super("SLES-15-010220", :security)
      end

      def validate(security_settings = nil)
        security_settings ||= default_security_settings
        return nil if !!security_settings&.enable_firewall

        action = Action.new(_("enable the firewall")) do
          security_settings.enable_firewall!
        end

        Issue.new(_("Firewall is not enabled"), action: action, scope: scope)
      end

    private

      def default_security_settings
        ::Installation::SecuritySettings.instance
      end
    end
  end
end
