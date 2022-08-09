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
#
require "installation/proposal_client"
require "y2security/security_policy"

module Y2Security
  module Clients
    # Proposal client to enable/disable security policies
    class SecurityPolicyProposal < ::Installation::ProposalClient
      include Yast::I18n
      include Yast::Logger

      LINKS = [
        LINK_ENABLE = "security-policy--enable".freeze,
        LINK_DISABLE = "security-policy--disable".freeze
      ].freeze

      LINK_DIALOG = "security_policy".freeze

      def initialize
        super
        Yast.import "UI"
        Yast.import "HTML"
        textdomain "security"
      end

      def description
        {
          # Proposal title
          "rich_text_title" => _("Security Policy"),
          # Menu entry label
          "menu_title"      => _("&Security Policy"),
          "id"              => LINK_DIALOG
        }
      end

      def make_proposal(_attrs)
        {
          "preformatted_proposal" => preformatted_proposal,
          "warning_level"         => warning_level,
          "links"                 => LINKS,
          "warning"               => warning_message
        }
      end

      def preformatted_proposal
        link = if stig_policy.enabled?
          _(
            "STIG is enabled (<a href=\"%s\">disable</a>)"
          ) % LINK_DISABLE
        else
          _(
            "STIG is not enabled (<a href=\"%s\">enable</a>)"
          ) % LINK_ENABLE
        end
        Yast::HTML.List([link])
      end

      def ask_user(param)
        chosen_link = param["chosen_id"]
        case chosen_link
        when LINK_DISABLE
          stig_policy.disable
        when LINK_ENABLE
          stig_policy.enable
        end

        { "workflow_result" => :again }
      end

    private

      def enable_stig
        stig_policy.enable
      end

      def disable_stig
        stig_policy.disable
      end

      def warning_message
        return nil unless stig_policy.enabled?

        issues = stig_policy.issues
        return nil if issues.empty?

        Yast::HTML.List(issues.map(&:message))
      end

      def warning_level
        :error
      end

      def stig_policy
        @stig_policy ||= Y2Security::SecurityPolicy.find(:stig)
      end
    end
  end
end
