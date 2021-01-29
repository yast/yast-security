# Copyright (c) [2021] SUSE LLC
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
require "yast2/execute"

module Security
  # Class for handling SELinux kernel params
  class Selinux
    include Yast::Logger
    Yast.import "Bootloader"

    GETENFORCE_PATH = "/usr/sbin/getenforce"
    private_constant :GETENFORCE_PATH

    class << self
      DEFAULT_POLICY_OPTIONS = {
        "security"  => :missing,
        "selinux"   => :missing,
        "enforcing" => :missing
      }.freeze
      private_constant :DEFAULT_POLICY_OPTIONS

      def define_policy(name, options = {})
        policies[name] = DEFAULT_POLICY_OPTIONS.merge(options)
      end

      def policies
        @policies ||= {}
      end

      def policy_keys
        DEFAULT_POLICY_OPTIONS.keys
      end
    end

    define_policy(:disabled)
    define_policy(:permissive, "security" => "selinux", "selinux" => "1", "enforcing" => :missing)
    define_policy(:enforcing, "security" => "selinux", "selinux" => "1", "enforcing" => "1")

    def initialize
      propose_policy if Yast::Mode.installation
    end

    # Returns the policy set in booting params
    def policy
      @policy ||= match_policy(policy_options_from_kernel) || :disabled
    end

    # Use the given policy for the next boot (in running system is needed to #save)
    def policy=(key)
      found_policy = find_policy(key)

      if found_policy
        log.debug("Changing SELinux to #{key} mode: #{found_policy}")

        @policy = key
      else
        log.debug("Unknown `#{key}` SELinux policy")
      end
    end

    # Returns the policy applied in the running system
    def running_policy
      Yast::Execute.locally!(GETENFORCE_PATH, stdout: :capture).chomp.downcase.to_sym
    rescue Cheetah::ExecutionFailed
      nil
    end

    # Propose a policy according to the value set in the control-file
    def propose_policy
      key = :enforcing # read it from control-file

      log.debug "Proposing the `#{key}` SELinux policy: #{@policy}"
      @policy = key
      save
    end

    def save
      update_policy

      Yast::Bootloader.Write unless Yast::Mode.installation
    end

    private

    def find_policy(key)
      self.class.policies[key]
    end

    def match_policy(policy_options)
      self.class.policies.key(policy_options)
    end

    def policy_options_from_kernel
      Hash[*self.class.policy_keys.flat_map { |key| [key, read_param(key)] }]
    end

    def read_param(key)
      Yast::Bootloader.kernel_param(:common, key.to_s)
    end

    def update_policy
      policy = find_policy(@policy)
      Yast::Bootloader.modify_kernel_params(**policy)
    end
  end
end
