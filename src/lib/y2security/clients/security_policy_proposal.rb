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
require "y2security/security_policies/unknown_rule"
require "bootloader/main_dialog"

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
          "rich_text_title" => _("Security Policies"),
          # Menu entry label
          "menu_title"      => _("&Security Policies"),
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
          "warning"               => warning
        }
      end

      # @see Installation::ProposalClient#ask_user
      def ask_user(param)
        action, id = parse_link(param["chosen_id"])
        result = :again
        case action
        when "toggle-policy"
          toggle_policy(id.to_sym)
        when "toggle-rule"
          toggle_rule(id)
        when "fix-rule"
          fix_rule(id)
        when "set-scap-action"
          policies_manager.scap_action = id.to_sym
        when "storage"
          result = open_client("inst_disk_proposal")
        when "bootloader"
          result = open_bootloader
        end

        { "workflow_sequence" => result }
      end

      # @return [LinksBuilder]
      attr_reader :links_builder

      # @see Installation::ProposalClient#preformatted_proposal
      def preformatted_proposal
        formatted_policies = policies.map do |policy|
          enabled = policies_manager.enabled_policy?(policy)
          rules = failing_rules[policy]

          presenter = PolicyPresenter.new(policy,
            enabled: enabled, failing_rules: rules, links_builder: links_builder,
            scap_action: policies_manager.scap_action)

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
        links = policies_links + rules_links + links_builder.links_for_scap_actions

        links.flatten.compact.uniq
      end

      # Returns the warning message
      #
      # @return [String,nil] warning message or nil if there are no failing rules
      def warning
        return nil if success?

        _("The current configuration does not comply with the enabled security policies.")
      end

      # Whether the proposal was successful
      #
      # @return [Boolean] true if the proposal was successful; false otherwise
      def success?
        rules = failing_rules.values.flatten
        rules.none? || rules.none?(&:enabled?)
      end

      # Returns the warning level
      #
      # Error if there are enabled failing rules
      #
      # @return [Symbol,nil] :error or nil
      def warning_level
        success? ? nil : :error
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

      # Toggles (enable/disable) the policy with the given ID
      #
      # @param id [Symbol] Policy ID
      def toggle_policy(id)
        policy = policies_manager.find_policy(id)
        return unless policy

        if policies_manager.enabled_policy?(policy)
          policies_manager.disable_policy(policy)
        else
          policies_manager.enable_policy(policy)
        end
      end

      # Toggles (enable/disable) the rule with the given ID
      #
      # @param id [String] Rule ID
      def toggle_rule(id)
        rule = find_rule(id)
        return unless rule

        rule.enabled? ? rule.disable : rule.enable
      end

      # Returns the rule with the given ID
      #
      # @param id [String] Rule ID
      # @return [SecurityPolicies::Rule, nil] nil if there is no rule with the given ID
      def find_rule(id)
        rules.find { |r| r.id == id }
      end

      # Tries to fix the rule with the given ID
      #
      # @param id [Integer] Rule ID
      def fix_rule(id)
        rule = find_rule(id)
        rule&.fix(target_config)
      end

      # Parses a link
      #
      # @see #ask_user
      #
      # @param link [String] A link containing the action and the ID of the element to act on
      # @return [Array<String>] Action and ID
      def parse_link(link)
        link.delete_prefix("#{PROPOSAL_ID}--").split(":")
      end

      # Convenience method to access the list of failing rules
      #
      # @return [Hash{SecurityPolicies::Policy => Array<SecurityPolicies::Rule>}]
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

      # Target config to work on
      #
      # @return [SecurityPolicies::TargetConfig]
      def target_config
        @target_config ||= SecurityPolicies::TargetConfig.new
      end

      # Runs a client, opening a new wizard dialog with only Cancel and Accept buttons.
      #
      # @param client [String] client name
      # @return [Symbol] client result
      def open_client(client)
        Yast::Wizard.OpenAcceptDialog

        # It is necessary to enable back and next for the Guided Setup wizard
        Yast::WFM.CallFunction(
          client,
          [{ "enable_back" => true, "enable_next" => true }]
        )
      ensure
        Yast::Wizard.CloseDialog
      end

      # Runs the bootloader configuration dialog and configures bootloader
      #
      # @return [Symbol] result
      def open_bootloader
        result = ::Bootloader::MainDialog.new.run_auto
        Yast::Bootloader.proposed_cfg_changed = true if result == :next

        result
      end

      # Helper class to builds unique hyperlink IDs (by scoping actions with a dialog ID and adding
      # an optional object ID).
      class LinksBuilder
        # Constructor
        #
        # @param dialog_id [String]
        def initialize(dialog_id)
          @dialog_id = dialog_id
        end

        # Possible links to use over a policy
        #
        # @param policy [SecurityPolicies::Policy]
        # @return [Array<String>]
        def links_for_policy(policy)
          [policy_toggle_link(policy)]
        end

        # Possible links to use over a rule
        #
        # @param rule [SecurityPolicies::Rule]
        # @return [Array<String>]
        def links_for_rule(rule)
          [
            rule_toggle_link(rule),
            rule_fix_link(rule)
          ]
        end

        # Possible links to set the SCAP action
        #
        # @return [Array<String>]
        def links_for_scap_actions
          # TODO: turn this into an enum or something similar
          [:none, :scan, :remediate].map { |a| scap_action_link(a) }
        end

        # Link for toggling (enable or disable) a policy
        #
        # @param policy [SecurityPolicies::Policy]
        # @return [String]
        def policy_toggle_link(policy)
          build_link("toggle-policy", policy.id)
        end

        # Link for toggling (enable or disable) a rule
        #
        # @param rule [SecurityPolicies::Rule]
        # @return [String]
        def rule_toggle_link(rule)
          build_link("toggle-rule", rule.id)
        end

        # Link for the action to fix a rule
        #
        # Rules from storage and bootloader scopes should open a client for modifying the settings.
        #
        # @param rule [SecurityPolicies::Rule]
        # @return [String, nil] nil if there is no action for the rule
        def rule_fix_link(rule)
          if rule.fixable?
            build_link("fix-rule", rule.id)
          elsif rule.scope == :storage
            build_link("storage")
          elsif rule.scope == :bootloader
            build_link("bootloader")
          end
        end

        # Link to set the SCAP action after installation
        #
        # @param scap_action [Symbol] SCAP action
        # @see Y2Security::SecurityPolicies::Manager#scap_action
        def scap_action_link(scap_action)
          build_link("set-scap-action", scap_action)
        end

      private

        # @return [String]
        attr_reader :dialog_id

        # Builds a link
        #
        # @param action [String] Action (e.g., "toggle", "fix", etc)
        # @param id [#to_s] ID of the element to act on
        #
        # @return [String]
        def build_link(action, id = nil)
          "#{dialog_id}--#{action}:#{id}"
        end
      end

      # Helper class to build the representation of a security policy
      class PolicyPresenter
        include Yast::I18n

        # @param policy [SecurityPolicies::Policy] policy to present
        # @param enabled [Boolean] Whether the policy is enabled
        # @param failing_rules [Array<SecurityPolicies::Rule>] Failing rules from the policy
        # @param links_builder [LinksBuilder] Object to build links
        # @param scap_action [Symbol] SCAP action on first boot (see Manager#scap_action)
        def initialize(policy, enabled:, failing_rules:, links_builder:, scap_action:)
          textdomain "security"

          @policy = policy
          @policy_enabled = enabled
          @failing_rules = failing_rules
          @links_builder = links_builder
          @scap_action = scap_action
        end

        # @return [String]
        def to_html
          toggle_link = links_builder.policy_toggle_link(policy)

          sections = []
          sections << if policy_enabled
            format(
              # TRANSLATORS: 'policy' is a security policy name; 'link' is just an HTML-like link
              _("%{policy} is enabled (<a href=\"%{link}\">disable</a>)"),
              policy: policy.name,
              link:   toggle_link
            )
          else
            format(
              # TRANSLATORS: 'policy' is a security policy name; 'link' is just an HTML-like link
              _("%{policy} is disabled (<a href=\"%{link}\">enable</a>)"),
              policy: policy.name,
              link:   toggle_link
            )
          end

          if policy_enabled
            sections << scap_action_description
            sections << rules_section
          end
          sections.join
        end

      private

        # @return [SecuiryPolicies::Policy]
        attr_reader :policy

        # @return [Boolean]
        attr_reader :policy_enabled

        # @return [Array<SecurityPolicies::Rule>]
        attr_reader :failing_rules

        # @return [LinksBuilder]
        attr_reader :links_builder

        # @return [Symbol]
        attr_reader :scap_action

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

          Yast::HTML.Para(Yast::HTML.Colorize(
            _("The following rules were already checked by the installer and are failing:"), "red")
          ) + rules_list(failing_rules)
        end

        # HTML section describing the disabled rules
        #
        # @note Unknown rules are filtered out.
        #
        # @see Yast::HTML
        #
        # @return [String]
        def disabled_rules_section
          disabled_rules = policy.rules.reject do |rule|
            rule.enabled? || rule.is_a?(SecurityPolicies::UnknownRule)
          end

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
          rules = rules.sort_by { |r| r.identifiers.first }
          items = rules.map { |r| RulePresenter.new(r, links_builder).to_html }

          Yast::HTML.List(items)
        end

        # Describes the action that will be performed on first boot
        #
        # @return [String]
        def scap_action_description
          case scap_action
          when :none
            text = _("No SCAP scan will be performed on first boot")
            actions = [:scan, :remediate]
          when :scan
            text = _("A full SCAP scan will be performed on first boot")
            actions = [:none, :remediate]
          else
            text = _("A full SCAP remediation will be performed on first boot")
            actions = [:none, :scan]
          end

          actions_links = actions.map { |a| scap_action_link(a) }.join(", ")
          Yast::HTML.Para("#{text} (#{actions_links})")
        end

        # Returns a link to set the SCAP action to the given value
        #
        # @param action [Symbol] SCAP action
        # @return [String]
        def scap_action_link(action)
          label =
            case action
            when :none
              _("do nothing")
            when :scan
              _("scan only")
            when :remediate
              _("scan and remediate")
            end

          format("<a href=\"%s\">%s</a>", links_builder.scap_action_link(action), label)
        end
      end

      # Helper class to build the representation of a rule
      class RulePresenter
        include Yast::I18n

        # Constructor
        #
        # @param rule [SecurityPolicies::Rule] Rule to present
        # @param links_builder [LinksBuilder]
        def initialize(rule, links_builder)
          textdomain "security"

          @rule = rule
          @links_builder = links_builder
        end

        # @return [String]
        def to_html
          second_line = (rule.identifiers + rule.references).join(", ")
          second_line << " (#{actions.join(", ")})" if actions.any?

          rule.description + Yast::HTML.Newline + second_line
        end

      private

        # @return [SecurityPolicies::Rule]
        attr_reader :rule

        # @return [LinksBuilder]
        attr_reader :links_builder

        # @see #to_html
        # @return [Array<String>]
        def actions
          # Disabling rule is not offered for now
          rule_actions = rule.enabled? ? [fix_action] : []
          rule_actions.compact
        end

        def toggle_action
          # TRANSLATORS: an action hyperlink
          text = rule.enabled? ? _("disable rule") : _("enable rule")

          build_action(text, links_builder.rule_toggle_link(rule))
        end

        def fix_action
          link = links_builder.rule_fix_link(rule)
          return nil unless link

          # TRANSLATORS: text for an action hyperlink
          text = link.match?(/--fix-rule:/) ? _("fix rule") : _("modify settings")

          build_action(text, link)
        end

        # HTML-like hyperlink element
        #
        # @param text [String] Text for the <a> tag
        # @param link [String] URL for the <a> tag
        #
        # @return [String]
        def build_action(text, link)
          format("<a href=\"%s\">%s</a>", link, text)
        end
      end
    end
  end
end
