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
require "y2security/security_policies/disa_stig_policy"
require "y2security/security_policies/target_config"
require "cfa/ssg_apply"
require "fileutils"

Yast.import "PackagesProposal"
Yast.import "Service"

module Y2Security
  module SecurityPolicies
    # Class to manage security policies
    class Manager
      # @return [:none, :scan, :remediate] action to perform after the installation. `:remediate`
      #   peforms a full remediation; `:scan` just scan the system and `:none` does nothing apart
      #   from installing the package
      # @see .known_scap_actions
      attr_reader :scap_action

      class UnknownSCAPAction < StandardError; end

      SCAP_ACTIONS = [:none, :scan, :remediate].freeze

      class << self
        def instance
          @instance ||= new
        end

        # Returns the known values for scap actions
        #
        # @return [Array<Symbol>]
        def known_scap_actions
          SCAP_ACTIONS
        end
      end

      include Yast::Logger

      # Environment variable to enable a security policy
      ENV_SECURITY_POLICY = "YAST_SECURITY_POLICY".freeze
      private_constant :ENV_SECURITY_POLICY

      # Currently enabled policy
      #
      # @return [Policy, nil]
      attr_reader :enabled_policy

      # A policy is automatically enabled according the the environment variable ENV_SECURITY_POLICY
      def initialize
        policy = policy_from_env(env_policy)
        self.enabled_policy = policy
        @scap_action = :scan
      end

      def scap_action=(value)
        raise UnknownSCAPAction unless self.class.known_scap_actions.include?(value)

        @scap_action = value
      end

      # Returns the list of known security policies
      #
      # @return [Array<Policy>]
      def policies
        @policies ||= [DisaStigPolicy.new].freeze
      end

      # Finds the security policy with the given id
      #
      # @param id [Symbol] Security policy id
      # @return [Policy, nil]
      def find_policy(id)
        policies.find { |p| p.id == id }
      end

      # Sets the enabled policy
      #
      # @param policy [Policy, nil]
      def enabled_policy=(policy)
        if policies.include?(policy)
          @enabled_policy = policy
          add_package
        else
          @enabled_policy = nil
          remove_package
        end
      end

      # @param config [TargetConfig]
      # @param scope [Symbol,nil] only consider rules with this scope.
      #   For example yast2-storage-ng will call this with :storage to
      #   only display rules that it can fix.
      # @param include_disabled [Boolean] whether to evaluate disabled rules
      #
      # @return [Array<Rule>]
      def failing_rules(config, scope: nil, include_disabled: false)
        return [] unless enabled_policy

        enabled_policy.failing_rules(config, scope: scope, include_disabled: include_disabled)
      end

      # Writes the security policy configuration to the target system
      #
      # @param config [TargetConfig]
      def write(config = TargetConfig.new)
        return unless enabled_policy

        write_failing_rules(config, enabled_policy)

        return if scap_action == :none

        write_config(enabled_policy)
        enable_service
      end

    private

      # Writes custom configuration for the ssg-apply script
      #
      # YaST installs the package ssg-apply if a security policy is enabled. That package provides
      # an script to be run on the first boot. The ssg-apply script invokes the oscap command using
      # options provided in the /etc/ssg-apply/override.conf file (if it exists), or in the
      # /etc/ssg-apply/default.conf file (if override.conf does not exist). Using an override.conf
      # file allows for custom configuration without modifying the default configuration file.
      #
      # Bear in mind that ssg-apply does not perform any kind of merging between both configuration
      # files.
      #
      # Only the #profile and #remediate options are written.
      def write_config(policy)
        copy_default_config
        file = CFA::SsgApply.load
        file.profile = policy.id.to_s
        file.remediate = (scap_action == :remediate) ? "yes" : "no"
        file.save
      end

      # Copies the default configuration file to the one used by YaST
      def copy_default_config
        root = Yast::WFM.scr_root
        source = ::File.join(root, CFA::SsgApply.default_file_path)
        target = ::File.join(root, CFA::SsgApply.override_file_path)
        ::FileUtils.copy(source, target) if File.exist?(source)
      end

      FAILING_RULES_FILE_PATH = "/var/log/YaST2/security_policy_failed_rules".freeze
      private_constant :FAILING_RULES_FILE_PATH

      # Writes the list of failing rules
      #
      # @param config [TargetConfig]
      # @param policy [Policy]
      def write_failing_rules(config, policy)
        root = Yast::WFM.scr_root
        path = ::File.join(root, FAILING_RULES_FILE_PATH)
        dir = File.dirname(path)
        FileUtils.mkdir_p(dir) unless Dir.exist?(dir)
        rules = policy.failing_rules(config)
        return if rules.none?

        content = rules.map(&:id).sort.join("\n") + "\n"
        File.write(path, content)
      end

      # Policy from the value indicated with the environment variable ENV_SECURITY_POLICY
      #
      # @param value [String]
      # @return [Policy, nil]
      def policy_from_env(value)
        return find_policy(:stig) if value.to_s.match?(/\Astig\z/i)

        log.warn("Security policy #{value} not found.")
        nil
      end

      # Value indicated with the environment variable ENV_SECURITY_POLICY
      #
      # @return [String, nil]
      def env_policy
        # Sort the keys to have a deterministic behavior and to prefer
        # all-uppercase over the other variants, then do a case insensitive
        # search
        key = ENV.keys.sort.find { |k| k.match(/\A#{ENV_SECURITY_POLICY}\z/i) }
        return nil unless key

        ENV[key]
      end

      SERVICE_NAME = "ssg-apply".freeze
      private_constant :SERVICE_NAME

      # Enables the ssg-apply service to remedy the system after the installation
      def enable_service
        Yast::Service.enable(SERVICE_NAME)
      end

      def add_package
        Yast::PackagesProposal.AddResolvables("security", :package, [SERVICE_NAME])
      end

      # Disables the service and removes the package to remedy the system after the installation
      def remove_package
        Yast::PackagesProposal.RemoveResolvables("security", :package, [SERVICE_NAME])
      end
    end
  end
end
