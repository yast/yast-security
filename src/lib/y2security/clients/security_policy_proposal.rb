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
require "y2security/security_policies/manager"

module Y2Security
  module Clients
    # Proposal client to enable/disable security policies
    class SecurityPolicyProposal < ::Installation::ProposalClient
      include Yast::I18n
      include Yast::Logger

      LINK_DIALOG = "security-policy".freeze

      class << self
        def issues
          @issues ||= IssuesCollection.new
        end

        attr_writer :issues
      end

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
        check_security_policies
        {
          "preformatted_proposal" => preformatted_proposal,
          "warning_level"         => warning_level,
          "links"                 => links,
          "warning"               => warning_message
        }
      end

      def preformatted_proposal
        Yast::HTML.List(
          policies.map { |p| policy_link(p) }
        )
      end

      def ask_user(param)
        action, id = parse_link(param["chosen_id"])
        case action
        when "disable"
          disable_policy(id.to_sym)
          refresh_packages
        when "enable"
          enable_policy(id.to_sym)
          refresh_packages
        when "fix"
          fix_issue(id.to_i)
        end

        { "workflow_result" => :again }
      end

    private

      def links
        main_links = policies.each_with_object([]) do |policy, all|
          all << action_link("enable", policy.id)
          all << action_link("disable", policy.id)
        end

        main_links + all_issues.each_with_index.map do |issue, idx|
          issue.action? ? action_link("fix", idx) : nil
        end.compact
      end

      def parse_link(link)
        link.delete_prefix("#{LINK_DIALOG}--").split(":")
      end

      def action_link(action, id)
        "#{LINK_DIALOG}--#{action}:#{id}"
      end

      def policies_manager
        Y2Security::SecurityPolicies::Manager.instance
      end

      # All policies
      #
      # @return [Array<Y2Security::SecurityPolicies::Policy>]
      def policies
        policies_manager.policies
      end

      # Enables the policy with the given id
      #
      # @param id [Symbol] Policy id
      def enable_policy(id)
        policy = policies_manager.find_policy(id)
        policies_manager.enable_policy(policy) if policy
      end

      # Disables the policy with the given id
      #
      # @param id [Symbol] Policy id
      def disable_policy(id)
        policy = policies_manager.find_policy(id)
        policies_manager.disable_policy(policy) if policy
      end

      def warning_message
        return nil if policies_manager.enabled_policies.none? || all_issues.empty?

        _("The system does not comply with the security policy.")
      end

      def policy_link(policy)
        if policies_manager.enabled_policy?(policy)
          format(
            # TRANSLATORS: 'policy' is a security policy name; 'link' is just an HTML-like link
            _("%{policy} is enabled (<a href=\"%{link}\">disable</a>)"),
            policy: policy.name,
            link:   action_link("disable", policy.id)
          ) + issues_list(issues.by_policy(policy))
        else
          format(
            # TRANSLATORS: 'policy' is a security policy name; 'link' is just an HTML-like link
            _("%{policy} is disabled (<a href=\"%{link}\">enable</a>)"),
            policy: policy.name,
            link:   action_link("enable", policy.id)
          )
        end
      end

      def all_issues
        issues.all
      end

      def warning_level
        :blocker
      end

      def check_security_policies
        self.class.issues = policies_manager.issues
      end

      # Adds or removes the packages needed by the policy to or from the Packages Proposal
      def refresh_packages
        policies.each do |policy|
          enabled = policies_manager.enabled_policy?(policy)
          method = enabled ? "AddResolvables" : "RemoveResolvables"

          Yast::PackagesProposal.public_send(method, "security", :package, policy.packages)
        end
      end

      def fix_issue(id)
        issue = all_issues[id]
        issue&.fix
      end

      def issues_list(issues)
        items = issues.each_with_index.map do |issue, idx|
          next issue.message unless issue.action?

          format(
            # TRANSLATORS: 'issue' is a security policy issue description;
            #  'link' is just an HTML-like link
            _("%{issue} (<a href=\"%{link}\">%{action}</a>)"),
            issue:  issue.message,
            link:   action_link("fix", idx),
            action: issue.action.message
          )
        end
        Yast::HTML.List(items)
      end

      def issues
        self.class.issues
      end
    end
  end
end
