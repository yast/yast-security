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

      # Returns the known security policy with the given ID
      #
      # @param id [Symbol] Security policy ID
      def find(id)
        all.find { |a| a.id == id }
      end

      # Enables a security policy
      # 
      # @fixme: perhaps policy could be a SecurityPolicy or a Symbol
      #
      # @param [SecurityPolicy] Security policy to enable
      def enable(policy)
        return if enabled.include?(policy)

        enabled << policy
      end

      # Returns the enabled policies
      def enabled
        @enabled ||= []
      end

      # Returns whether the policy is enabled or not
      def enabled?(policy)
        enabled.include?(policy)
      end

      # Disables a security policy
      #
      # @param [SecurityPolicy] Security policy to disable
      def disable(policy)
        enabled.filter! { |p| p != policy }
      end

      # Disables all security policies
      def reset
        enabled.clear
      end
    end

    # @param id [String] Security policy ID (kind of internal identifier)
    # @param name [String] Security policy name
    def initialize(id, name)
      @id = id
      @name = name
    end

    # @fixme I am not sure about this API. We need a way (e.g., passing a 'force' argument, adding a
    # #reload method, using a different validator -from outside-) to re-run the validation again.
    def valid?
      validator.valid?
    end

    def errors
      validator.errors
    end

    def enable
      self.class.enable(self)
    end

    def disable
      self.class.disable(self)
    end

    def enabled?
      self.class.enabled?(self)
    end

  private

    def validator
      @validator ||= SecurityPolicyValidator.for(self)
    end

    STIG = new(:stig, "STIG")
  end
end
