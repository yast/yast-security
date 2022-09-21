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
require "singleton"
require "y2security/security_policies/disa_stig_policy"
require "cfa/ssg_apply"

Yast.import "PackagesProposal"

module Y2Security
  module SecurityPolicies
    # Class to manage security policies
    class Manager
      class << self
        def instance
          @instance ||= new
        end
      end

      include Yast::Logger

      # Environment variable to enable security policies
      #
      # Its value contains "comma-separate" ids of the policies to enable
      ENV_SECURITY_POLICIES = "YAST_SECURITY_POLICIES".freeze
      private_constant :ENV_SECURITY_POLICIES

      # Currently enabled policies
      #
      # @return [Array<Policy>]
      attr_reader :enabled_policies

      # Policies are automatically enabled according the the environment variable
      # ENV_SECURITY_POLICIES
      def initialize
        @enabled_policies = []

        enable_policies
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

      # Enables the given policy
      #
      # @param policy [Policy]
      def enable_policy(policy)
        return unless policies.include?(policy)

        @enabled_policies.push(policy).uniq!
        enable_service
      end

      # Disables the given policy
      #
      # @param policy [Policy]
      def disable_policy(policy)
        return unless policies.include?(policy)

        @enabled_policies.delete(policy)
        disable_service if @enabled_policies.empty?
      end

      # Whether the given policy is enabled
      #
      # @param policy [Policy]
      # @return [Boolean]
      def enabled_policy?(policy)
        @enabled_policies.include?(policy)
      end

      # @param config [TargetConfig]
      # @param scope [Symbol,nil] only consider rules with this scope.
      #   For example yast2-storage-ng will call this with :storage to
      #   only display rules that it can fix.
      # @return [Hash<Policy, Array<Rule>>]
      def failing_rules(config, scope: nil, include_disabled: false)
        enabled_policies.each_with_object({}) do |policy, result|
          result[policy] =
            policy.failing_rules(config, scope: scope, include_disabled: include_disabled)
        end
      end

      # Writes custom configuration for the ssg-apply script
      #
      # YaST installs the package ssg-apply if a security policy is enabled. That package provides
      # an script to be run on the first boot. The ssg-apply script invokes the oscap command using
      # options provided in the /etc/ssg-apply/override.conf file (if it exists), or in the
      # /etc/ssg-apply/default.conf file (if override.conf does not exist). Using an override.conf
      # file allows for custom configuration without modifying the default configuration file.
      #
      # Only the #profile and #disabled-rules options are written.
      def write_config
        # Only one policy is expected to be enabled
        policy = policies.find { |p| enabled_policy?(p) }

        id = policy&.id || ""
        rules = policy&.rules || []

        file = CFA::SsgApply.load
        file.profile = id.to_s
        file.disabled_rules = rules.reject(&:enabled?).map(&:id)
        file.save
      end

    private

      # Enables policies according to the environment variable ENV_SECURITY_POLICIES
      def enable_policies
        policies_from_env.each { |p| enable_policy(p) }
      end

      # Policies from the values indicated with the environment variable ENV_SECURITY_POLICIES
      #
      # @return [Array<Policy>]
      def policies_from_env
        env_policies.map { |v| policy_from_env(v) }.compact.uniq
      end

      # Policy from one of the values indicated with the environment variable ENV_SECURITY_POLICIES
      #
      # @param value [String]
      # @return [Policy, nil]
      def policy_from_env(value)
        return find_policy(:disa_stig) if value.match?(/\Adisa_stig\z/i)

        log.warn("Security policy #{value} not found.")
        nil
      end

      # Values indicated with the environment variable ENV_SECURITY_POLICIES
      #
      # @return [Array<String>]
      def env_policies
        # Sort the keys to have a deterministic behavior and to prefer
        # all-uppercase over the other variants, then do a case insensitive
        # search
        key = ENV.keys.sort.find { |k| k.match(/\A#{ENV_SECURITY_POLICIES}\z/i) }
        return [] unless key

        ENV[key].split(",")
      end

      SERVICE_NAME = "ssg-apply".freeze
      private_constant :SERVICE_NAME

      # Adds the package and enables the service to remedy the system after the installation
      def enable_service
        return if enabled_services.include?(SERVICE_NAME)

        enabled_services << SERVICE_NAME
        Yast::PackagesProposal.AddResolvables("security", :package, [SERVICE_NAME])
      end

      # Disables the service and removes the package to remedy the system after the installation
      def disable_service
        return unless enabled_services.include?(SERVICE_NAME)

        enabled_services.delete(SERVICE_NAME)
        Yast::PackagesProposal.RemoveResolvables("security", :package, [SERVICE_NAME])
      end

      # Return the list of enabled services
      #
      # FIXME: avoid a cyclic dependency with yast2-installation
      #
      # @return [Array<String>] List of enabled services
      def enabled_services
        require "installation/services" unless defined?(::Installation::Services)
        ::Installation::Services.enabled
      rescue LoadError
        log.warn("Could not load the list of enabled services. " \
          "Make sure yast2-installation is installed.")
        []
      end
    end
  end
end
