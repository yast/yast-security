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
  class SelinuxConfig
    include Yast::Logger
    Yast.import "Bootloader"

    attr_reader :policy

    def initialize
      propose_policy if Yast::Mode.installation
      @policy = configured_policy
    end

    # Returns the policy applied in the running system
    def running_policy
      Yast::Execute.locally!(GETENFORCE_PATH, stdout: :capture).chomp.downcase.to_sym
    rescue Cheetah::ExecutionFailed
      log.debug("`#{GETENFORCE_PATH}` not available. SELinux or selinux-tools missing")
      :disabled
    end

    # If current policy value is different to the configured one
    def changed?
      @policy != configured_policy
    end

    # Use the given policy for the next boot (in running system is needed to #save)
    def update_policy(policy_key)
      found_policy = find_policy(policy_key)

      if found_policy
        log.info("Changing SELinux configuration to `#{policy_key}` policy: #{found_policy}")

        @policy = policy_key
      else
        log.info("Unknown `#{policy_key}` SELinux policy")
      end
    end
    alias_method :policy=, :update_policy

    def save
      policy_options = find_policy(policy)

      return unless policy_options && changed?

      log.info("Writting SELinux kernel params: #{policy_options}")

      Yast::Bootloader.modify_kernel_params(**policy_options)
      Yast::Bootloader.Write unless Yast::Mode.installation
    end

    private

    GETENFORCE_PATH = "/usr/sbin/getenforce".freeze
    private_constant :GETENFORCE_PATH

    POLICY_KEYS = ["security", "selinux", "enforcing"].freeze
    private_constant :POLICY_KEYS

    POLICIES = {
      disabled:   { "security" => :missing, "selinux" => :missing, "enforcing" => :missing },
      permissive: { "security" => "selinux", "selinux" => "1", "enforcing" => :missing },
      enforcing:  { "security" => "selinux", "selinux" => "1", "enforcing" => "1" },
    }.freeze
    private_constant :POLICIES

    def configured_policy
      match_policy(policy_options_from_kernel) || :disabled
    end

    # Propose a policy according to the value set in the control-file
    def propose_policy
      key = :enforcing # read it from control-file

      log.info "Proposing the `#{key}` SELinux policy"
      update_policy(policy_key)
      save
    end

    def find_policy(key)
      POLICIES[key]
    end

    def match_policy(policy_options)
      POLICIES.key(policy_options)
    end

    def policy_options_from_kernel
      Hash[*POLICY_KEYS.flat_map { |key| [key, read_param(key)] }]
    end

    def read_param(key)
      Yast::Bootloader.kernel_param(:common, key.to_s)
    end
  end
end
