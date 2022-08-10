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
        check_security_policy
        {
          "preformatted_proposal" => preformatted_proposal,
          "warning_level"         => warning_level,
          "links"                 => LINKS,
          "warning"               => warning_message
        }
      end

      def preformatted_proposal
        link = if disa_stig_policy.enabled?
          format(
            # TRANSLATORS: 'policy' is a security policy name; 'link' is just an HTML-like link
            _("%{policy} is enabled (<a href=\"%{link}\">disable</a>)"),
            policy: disa_stig_policy.name,
            link:   LINK_DISABLE
          ) + Yast::HTML.List(disa_stig_issues.map(&:message))
        else
          format(
            # TRANSLATORS: 'policy' is a security policy name; 'link' is just an HTML-like link
            _("%{policy} is disabled (<a href=\"%{link}\">enable</a>)"),
            policy: disa_stig_policy.name,
            link:   LINK_ENABLE
          )
        end
        Yast::HTML.List([link])
      end

      def ask_user(param)
        chosen_link = param["chosen_id"]
        case chosen_link
        when LINK_DISABLE
          disa_stig_policy.disable
        when LINK_ENABLE
          disa_stig_policy.enable
        end

        { "workflow_result" => :again }
      end

    private

      attr_reader :disa_stig_issues

      def warning_message
        return nil unless disa_stig_policy.enabled?

        return nil if disa_stig_issues.empty?

        _("The system does not comply with the security policy.")
      end

      def warning_level
        :blocker
      end

      def check_security_policy
        @disa_stig_issues =
          disa_stig_policy.enabled? ? disa_stig_policy.validate : Y2Issues::List.new
      end

      def disa_stig_policy
        @disa_stig_policy ||= Y2Security::SecurityPolicy.find(:disa_stig)
      end
    end
  end
end
