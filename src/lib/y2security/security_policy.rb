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

require "y2security/security_policy_validator"

module Y2Security
  # This class represents a security policy
  #
  # It offers an API to get the security policies and run validations.
  #
  # @example Get all known security policies
  #   SecurityPolicy.all #=> [#<Y2Security::SecurityPolicy...>]
  #   SecurityPolicy.all.map(&:name) #=> ["STIG"]
  #
  # @example Run STIG networking validation
  #   policy = SecurityPolicy.find(:stig)
  #   policy.validate.map(&:to_message) #=> ["Wireless devices are not allowed"]
  class SecurityPolicy
    # @return [Symbol] Security policy ID
    attr_reader :id
    # @return [String] Security policy name
    attr_reader :name

    class << self
      # Returns the list of known security policies
      #
      # @return [Array<SecurityPolicy>]
      def all
        @all ||= [STIG]
      end

      # Returns the security policy with the given ID
      #
      # @param id [Symbol] Security policy ID
      def find(id)
        all.find { |a| a.id == id }
      end

      # Returns the enabled policies
      #
      # @return [Array<SecurityPolicy>] List of enabled security policies
      def enabled
        all.select(&:enabled?)
      end
    end

    # @param id [String] Security policy ID (kind of internal identifier)
    # @param name [String] Security policy name
    def initialize(id, name)
      @id = id
      @name = name
      @enabled = false
    end

    # Validates whether the current configuration matches the policy
    #
    # @return [Y2Issues::List] List of validation issues
    def validate
      validator.validate
    end

    # Enables the policy
    def enable
      @enabled = true
    end

    # Disables the policy
    def disable
      @enabled = false
    end

    # Determines whether the policy is enabled or not
    #
    # @return [Boolean] true if it is enabled; false otherwise
    def enabled?
      @enabled
    end

  private

    # Returns the associated validator
    #
    # @return [SecurityPolicyValidator]
    def validator
      @validator ||= SecurityPolicyValidator.for(self)
    end

    STIG = new(:stig, "Defense Information Systems Agency STIG")
  end
end
