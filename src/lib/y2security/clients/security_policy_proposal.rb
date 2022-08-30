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
    # Proposal client to enable, disable and check security policies
    class SecurityPolicyProposal < ::Installation::ProposalClient
      include Yast::I18n
      include Yast::Logger

      LINK_DIALOG = "security-policy".freeze

      class << self
        # Collection of issues found for enabled policies
        #
        # The list of issues is shared by SecurityPolicyProposal instances.
        #
        # @return [IssuesCollection]
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

      # @see Installation::ProposalClient#description
      def description
        {
          # Proposal title
          "rich_text_title" => _("Security Policy"),
          # Menu entry label
          "menu_title"      => _("&Security Policy"),
          "id"              => LINK_DIALOG
        }
      end

      # @see Installation::ProposalClient#make_proposal
      def make_proposal(_attrs)
        check_security_policies
        {
          "preformatted_proposal" => preformatted_proposal,
          "warning_level"         => warning_level,
          "links"                 => links,
          "warning"               => warning_message
        }
      end

      # @see Installation::ProposalClient#preformatted_proposal
      def preformatted_proposal
        Yast::HTML.List(
          policies.map { |p| policy_link(p) }
        )
      end

      # @see Installation::ProposalClient#ask_user
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

      # Returns the list of valid links for the proposal
      #
      # The list includes links to enable, disable and automatically fix issues.
      #
      # @return [Array<String>]
      def links
        main_links = policies.each_with_object([]) do |policy, all|
          all << action_link("enable", policy.id)
          all << action_link("disable", policy.id)
        end

        main_links + all_issues.each_with_index.map do |issue, idx|
          issue.action? ? action_link("fix", idx) : nil
        end.compact
      end

      # Parses a link
      #
      # @param link [Array<String, String>] An array containing the the action
      #   and the id of the element to act on
      # @see #ask_user
      def parse_link(link)
        link.delete_prefix("#{LINK_DIALOG}--").split(":")
      end

      # Builds a link
      #
      # @param action [String] Action ("enable", "disable" or "fix")
      # @param id [#to_s] id of the element to act on
      # @return [String]
      def action_link(action, id)
        "#{LINK_DIALOG}--#{action}:#{id}"
      end

      # Convenience method to get the instance of the policies manager
      #
      # @return [Y2Security::SecurityPolicies::Manager]
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

      # Returns a warning message when policies issues are found
      #
      # @return [String,nil] Warning message or nil if no issues were found
      def warning_message
        return nil if policies_manager.enabled_policies.none? || all_issues.empty?

        _("The system does not comply with the security policy.")
      end

      # Builds a link to act on a policy
      #
      # A policy can be enabled, disabled or fixed (if possible)
      #
      # @param policy [Y2Security::SecurityPolicies::Policy]
      # @return [String]
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

      # Returns the warning level
      #
      # Always blocker issues
      #
      # @return [Symbol] :blocker
      def warning_level
        :blocker
      end

      # Runs the security policies checks
      #
      # Calling this method updates the list of issues in
      # Y2Security::Clients::SecurityProposalProposal.issues.
      #
      # @see Y2Security::SecurityPolicies::Manager#issues
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

      # Tries to fix the given issue in the given position
      #
      # @param idx [Integer]
      # @return [Y2Security::SecurityPolicies::Issue]
      # @see #all_issues
      def fix_issue(idx)
        issue = all_issues[idx]
        issue&.fix
      end

      # Returns the HTML representation of a list of issues
      #
      # @param issues [Array<Y2Security::SecurityPolicies::Issue>]
      # @return [String]
      # @see Yast::HTML.List
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

      # Convenience method to access the list of found issues
      def issues
        self.class.issues
      end

      # Returns the list of issues
      #
      # The reason to hold a variable with the list is that issues are identified by its position in
      # the list, so we need to be sure that the list does not change.
      def all_issues
        @all_issues ||= issues.all
      end
    end
  end
end
