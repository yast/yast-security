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
require "installation/proposal_client"
require "y2security/security_policies/manager"
require "y2security/security_policies/target_config"

Yast.import "Wizard"

module Y2Security
  module Clients
    # Proposal client to enable, disable and check security policies
    class SecurityPolicyProposal < ::Installation::ProposalClient
      include Yast::I18n
      include Yast::Logger

      PROPOSAL_ID = "security-policy".freeze

      class << self
        # Collection of failing rules from the enabled policies
        #
        # The list of failing rules is shared by SecurityPolicyProposal instances.
        #
        # @return [Hash{SecurityPolicies::Policy => Array<SecurityPolicies::Rule>}]
        def failing_rules
          @failing_rules ||= {}
        end

        attr_writer :failing_rules
      end

      def initialize
        super
        Yast.import "UI"
        Yast.import "HTML"
        textdomain "security"

        @links_builder = LinksBuilder.new(PROPOSAL_ID)
      end

      # @see Installation::ProposalClient#description
      def description
        {
          # Proposal title
          "rich_text_title" => _("Security Policy"),
          # Menu entry label
          "menu_title"      => _("&Security Policy"),
          "id"              => PROPOSAL_ID
        }
      end

      # @see Installation::ProposalClient#make_proposal
      def make_proposal(_attrs)
        check_security_policies
        {
          "preformatted_proposal" => preformatted_proposal,
          "links"                 => links,
          "warning_level"         => warning_level,
          "warning"               => nil
        }
      end

      # @see Installation::ProposalClient#ask_user
      def ask_user(param)
        action, id = parse_link(param["chosen_id"])
        case action
        when "toggle-policy"
          toggle_policy(id.to_sym)
          refresh_packages
        when "toggle-rule"
          toggle_rule(id)
        when "fix-rule"
          fix_rule(id)
        when "storage"
          storage_client
        end

        { "workflow_result" => :again }
      end

      # @return [LinksBuilder]
      attr_reader :links_builder

      # @see Installation::ProposalClient#preformatted_proposal
      def preformatted_proposal
        formatted_policies = policies.map do |policy|
          enabled = policies_manager.enabled_policy?(policy)
          rules = failing_rules[policy]

          presenter = PolicyPresenter.new(policy,
            enabled: enabled, failing_rules: rules, links_builder: links_builder)

          presenter.to_html
        end

        formatted_policies[0..-2] = formatted_policies[0..-2].map { |p| p + Yast::HTML.Newline }

        Yast::HTML.List(formatted_policies)
      end

    private

      # Returns the list of valid links for the proposal
      #
      # @return [Array<String>]
      def links
        policies_links = policies.map { |p| links_builder.links_for_policy(p) }
        rules_links = rules.map { |r| links_builder.links_for_rule(r) }
        links = policies_links + rules_links

        links.flatten.compact.uniq
      end

      # Returns the warning level
      #
      # Blocker if there are enabled failing rules
      #
      # @return [Symbol] :blocker
      def warning_level
        rules = failing_rules.values.flatten

        return :warning if rules.none? || rules.none?(&:enabled?)

        :blocker
      end

      # Runs the security policies checks
      #
      # Calling this method updates the list of failing rules in
      # Y2Security::Clients::SecurityProposalProposal.failing_rules
      #
      # @see Y2Security::SecurityPolicies::Manager#failing_rules
      def check_security_policies
        self.class.failing_rules =
          policies_manager.failing_rules(target_config)
      end

      # Enables the policy with the given id
      #
      # @param id [Symbol] Policy id
      def toggle_policy(id)
        policy = policies_manager.find_policy(id)
        return unless policy

        method = policies_manager.enabled_policy?(policy) ? "disable_policy" : "enable_policy"
        policies_manager.public_send(method, policy)
      end

      def toggle_rule(id)
        rule = find_rule(id)
        return unless rule

        rule.enabled? ? rule.disable : rule.enable
      end

      def find_rule(id)
        rules.find { |r| r.id == id }
      end

      # Tries to fix the given rule
      #
      # @param id [Integer] Rule id
      def fix_rule(id)
        rule = find_rule(id)
        rule&.fix(target_config)
      end

      # Adds or removes the packages needed by the policy to or from the Packages Proposal
      def refresh_packages
        policies.each do |policy|
          enabled = policies_manager.enabled_policy?(policy)
          method = enabled ? "AddResolvables" : "RemoveResolvables"

          Yast::PackagesProposal.public_send(method, "security", :package, policy.packages)
        end
      end

      # Parses a link
      #
      # @param link [Array<String, String>] An array containing the the action
      #   and the id of the element to act on
      # @see #ask_user
      def parse_link(link)
        link.delete_prefix("#{PROPOSAL_ID}--").split(":")
      end

      # Convenience method to access the list of failing rules
      def failing_rules
        self.class.failing_rules
      end

      # All policies
      #
      # @return [Array<Y2Security::SecurityPolicies::Policy>]
      def policies
        policies_manager.policies
      end

      # All rules from all policies
      #
      # @return [Array<Y2Security::SecurityPolicies::Rule>]
      def rules
        policies.map(&:rules).flatten
      end

      # Convenience method to get the instance of the policies manager
      #
      # @return [Y2Security::SecurityPolicies::Manager]
      def policies_manager
        Y2Security::SecurityPolicies::Manager.instance
      end

      # @return [SecurityPolicies::TargetConfig]
      def target_config
        @target_config ||= SecurityPolicies::TargetConfig.new
      end

      # Runs the storage client, opening a new wizard dialog with only Cancel and Accept buttons.
      #
      # @return [Symbol] client result
      def storage_client
        Yast::Wizard.OpenAcceptDialog

        # It is necessary to enable back and next for the Guided Setup wizard
        Yast::WFM.CallFunction(
          "inst_disk_proposal",
          [{ "enable_back" => true, "enable_next" => true }]
        )
      ensure
        Yast::Wizard.CloseDialog
      end

      # Builds unique hyperlink IDs
      # (by scoping actions with a dialog ID and adding an optional object ID).
      class LinksBuilder
        def initialize(dialog_id)
          @dialog_id = dialog_id
        end

        def links_for_policy(policy)
          [policy_toggle_link(policy)]
        end

        def links_for_rule(rule)
          [
            rule_toggle_link(rule),
            rule_fix_link(rule)
          ]
        end

        def policy_toggle_link(policy)
          build_link("toggle-policy", policy.id)
        end

        def rule_toggle_link(rule)
          build_link("toggle-rule", rule.id)
        end

        def rule_fix_link(rule)
          if rule.fixable?
            build_link("fix-rule", rule.id)
          elsif rule.scope == :storage
            build_link("storage")
          end
        end

      private

        attr_reader :dialog_id

        # Builds a link
        #
        # @param action [String] Action ("enable", "disable" or "fix")
        # @param id [#to_s] id of the element to act on
        # @return [String]
        def build_link(action, id = nil)
          "#{dialog_id}--#{action}:#{id}"
        end
      end

      # Builds the representation of a security policy
      class PolicyPresenter
        include Yast::I18n

        # @param policy [SecurityPolicies::Policy]
        # @param failing_rules [Array<SecurityPolicies::Rule>]
        # @param links_builder [LinksBuilder]
        def initialize(policy, enabled:, failing_rules:, links_builder:)
          textdomain "security"

          @policy = policy
          @policy_enabled = enabled
          @failing_rules = failing_rules
          @links_builder = links_builder
        end

        # @return [String]
        def to_html
          toggle_link = links_builder.policy_toggle_link(policy)

          if policy_enabled
            format(
              # TRANSLATORS: 'policy' is a security policy name; 'link' is just an HTML-like link
              _("%{policy} is enabled (<a href=\"%{link}\">disable</a>)"),
              policy: policy.name,
              link:   toggle_link
            ) + rules_section
          else
            format(
              # TRANSLATORS: 'policy' is a security policy name; 'link' is just an HTML-like link
              _("%{policy} is disabled (<a href=\"%{link}\">enable</a>)"),
              policy: policy.name,
              link:   toggle_link
            )
          end
        end

      private

        attr_reader :policy

        attr_reader :policy_enabled

        attr_reader :failing_rules

        attr_reader :links_builder

        # HTML section describing the failing and disabled rules
        #
        # @see Yast::HTML
        #
        # @return [String]
        def rules_section
          [failing_rules_section, disabled_rules_section].compact.join
        end

        # HTML section describing the failing rules
        #
        # @see Yast::HTML
        #
        # @return [String]
        def failing_rules_section
          return nil if failing_rules.none?

          Yast::HTML.Para(Yast::HTML.Colorize(_("The following rules are failing:"), "red")) +
            rules_list(failing_rules)
        end

        # HTML section describing the disabled rules
        #
        # @see Yast::HTML
        #
        # @return [String]
        def disabled_rules_section
          disabled_rules = policy.rules.reject(&:enabled?)

          return nil if disabled_rules.none?

          Yast::HTML.Para(_("The following rules are disabled:")) + rules_list(disabled_rules)
        end

        # HTML list of rules
        #
        # @see Yast::HTML.List
        #
        # @param rules [Array<Y2Security::SecurityPolicies::Rule>] Rules to display
        # @return [String]
        def rules_list(rules)
          items = rules.map { |r| RulePresenter.new(r, links_builder).to_html }

          Yast::HTML.List(items)
        end
      end

      # Builds the representation of a rule
      class RulePresenter
        include Yast::I18n

        #  @param rule [SecurityPolicies::Rule]
        def initialize(rule, links_builder)
          textdomain "security"

          @rule = rule
          @links_builder = links_builder
        end

        def to_html
          return message if actions.none?

          all_actions = actions.join(", ")
          "#{message} (#{all_actions})"
        end

      private

        attr_reader :rule

        attr_reader :links_builder

        def message
          "#{rule.id} #{rule.description}"
        end

        def actions
          rule_actions = [toggle_action]
          rule_actions << fix_action if rule.enabled?

          rule_actions.compact
        end

        def toggle_action
          text = rule.enabled? ? _("disable rule") : _("enable rule")

          build_action(text, links_builder.rule_toggle_link(rule))
        end

        def fix_action
          link = links_builder.rule_fix_link(rule)
          return nil unless link

          text = (rule.scope == :storage) ? _("open partitioning") : _("fix rule")

          build_action(text, link)
        end

        def build_action(text, link)
          format("<a href=\"%s\">%s</a>", link, text)
        end
      end
    end
  end
end
