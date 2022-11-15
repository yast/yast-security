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

module Y2Security
  module SecurityPolicies
    # Helper class to build the HTML representation of a rule
    class RulePresenter
      include Yast::I18n

      # Constructor
      #
      # @param rule [SecurityPolicies::Rule] Rule to present
      # @param toggle_link [String, nil] Link to use with for the toggle action hyperlink. Use nil
      #   to omit the toggle hyperlink.
      # @param fix_link [String, nil] Link to use with for the fix action hyperlink. Use nil to omit
      #   the fix hyperlink.
      def initialize(rule, toggle_link: nil, fix_link: nil)
        textdomain "security"

        @rule = rule
        @toggle_link = toggle_link
        @fix_link = fix_link
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

      # @return [String, nil]
      attr_reader :toggle_link

      # @return [String, nil]
      attr_reader :fix_link

      # @see #to_html
      # @return [Array<String>]
      def actions
        rule_actions = [toggle_action]
        rule_actions << fix_action if rule.enabled?

        rule_actions.compact
      end

      def toggle_action
        return nil unless toggle_link

        # TRANSLATORS: text for an action hyperlink
        text = rule.enabled? ? _("disable rule") : _("enable rule")

        build_action(text, toggle_link)
      end

      def fix_action
        return nil unless fix_link

        # TRANSLATORS: text for an action hyperlink
        text = rule.fixable? ? _("fix rule") : _("modify settings")

        build_action(text, fix_link)
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
