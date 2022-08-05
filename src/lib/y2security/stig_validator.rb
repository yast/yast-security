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
require "y2security/security_policy_validator"
require "y2security/security_policy_issues"
require "y2network/connection_config/wireless"

Yast.import "Lan"

module Y2Security
  # Validator for the STIG security policy
  class StigValidator < SecurityPolicyValidator
    # Returns the issues found for the given scope
    #
    # @param scope [Symbol] Scope to validate (:network, :storage, :bootloader, etc.)
    def issues(scope)
      found_issues = send("#{scope}_issues")
      SecurityPolicyIssues.new(found_issues)
    end

  private

    def network_issues
      return [] if Yast::Lan.yast_config.nil?

      wireless = Yast::Lan.yast_config.connections.select do |conn|
        conn.is_a?(Y2Network::ConnectionConfig::Wireless) &&
          conn.startmode&.name != "off"
      end
      return [] if wireless.empty?

      [
        Y2Issues::Issue.new(
          "No wireless connections are allowed", severity: :error,
          location: Y2Issues::Location.new("proposal", "network")
        )
      ]
    end
  end
end
