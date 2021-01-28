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

    POLICY_KEYS = ["security", "selinux", "enforcing"]
    private_constant :POLICY_KEYS

    ENABLE_POLICY = { "security" => "selinux", "selinux" => "1" }
    private_constant :ENABLE_POLICY

    DISABLE_POLICY = Hash[*POLICY_KEYS.flat_map { |key| [key, :missing] }]
    private_constant :DISABLE_POLICY

    POLICIES = {
      :disabled   => DISABLE_POLICY,
      :permissive => ENABLE_POLICY.merge("enforcing" => :missing),
      :enforcing  => ENABLE_POLICY.merge("enforcing" => "1")
    }
    private_constant :POLICIES

    attr_reader :changed

    def initialize
      propose_policy if Yast::Mode.installation
    end

    # Returns the policy set in booting params
    def policy
      POLICIES.key(policy_from_kernel_params) || :disabled
    end

    # Use the given policy for the next boot (in running system is needed to #save)
    def policy=(key)
      if POLICIES.keys.include?(key)
        log.debug("Changing SELinux to #{key} mode: #{POLICIES[key]}")

        update_policy(*POLICIES[key])
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

      update_policy(POLICIES[key])
      key
    end

    def save
      Yast::Bootloader.Write
    end

    private

    def policy_from_kernel_params
      Hash[*POLICY_KEYS.flat_map { |key| [key, read_param(key)] }]
    end

    def read_param(key)
      Yast::Bootloader.kernel_param(:common, key.to_s)
    end

    def update_policy(*params)
      Yast::Bootloader.modify_kernel_params(*params)
    end
  end
end
