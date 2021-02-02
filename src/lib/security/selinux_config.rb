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
    extend Yast::I18n
    include Yast::I18n
    include Yast::Logger

    Yast.import "Bootloader"
    Yast.import "ProductFeatures"

    attr_reader :mode

    # Constructor
    def initialize
      @mode = initial_mode
    end

    # Return the initial SELinux mode
    #
    # It can be the proposed one if running in an installation or the configured mode for a
    # running system
    #
    # @return [Symbol]
    def initial_mode
      return @initial_mode if @initial_mode

      propose_mode if Yast::Mode.installation

      @initial_mode = configured_mode
    end

    # Returns the mode applied in the running system
    #
    # @note the system can be booted with a different SELinux mode that the configured one. To
    #  know the running mode getenforce tool is used.
    #
    # @return [Symbol] running SELinux mode if command executed successfully; :disabled otherwise
    def running_mode
      Yast::Execute.locally!(GETENFORCE_PATH, stdout: :capture).chomp.downcase.to_sym
    rescue Cheetah::ExecutionFailed
      log.debug("`#{GETENFORCE_PATH}` not available. SELinux or selinux-tools missing")
      :disabled
    end

    # Returns available SELinux modes
    #
    # @return [Hash{Symbol=><String, Symbol>}] collection holding available modes ids and names
    def available_modes
      MODES.map { |id, mode| { id: id, name: _(mode[:name]) } }
    end

    # Set the mode to given value
    #
    # @note using nil means to set SELinux mode as disabled.
    #
    # @param id [String, Symbol, nil] a SELinux mode identifier
    # @return [Symvol] given mode id as a symbol or :disabled
    def mode=(id)
      @mode = id&.to_sym || :disabled
    end

    # Set current mode options as kernel parameters for the next boot
    #
    # @note it does not write the changes when running in installation mode, where only sets the
    #   kernel params in memory, since the Yast::Bootloader.Write will be performed at the end of
    #   installation.
    #
    # @see Yast::Bootloader#modify_kernel_params
    #
    # @return [Boolean] false if there area not mode options or nothing changed; true otherwise
    def save
      mode_options = find_mode_options(mode)

      unless mode_options
        log.info("Unknown `#{mode}` SELinux mode")
        return false
      end

      changed = Yast::Bootloader.modify_kernel_params(**mode_options)
      changed = Yast::Bootloader.Write if changed && !Yast::Mode.installation
      changed
    end

    private

    # Path to the SELinux getenforce command
    GETENFORCE_PATH = "/usr/sbin/getenforce".freeze
    private_constant :GETENFORCE_PATH

    # Known keys for setting a SELinux mode via kernel command line
    MODE_KEYS = ["security", "selinux", "enforcing"].freeze
    private_constant :MODE_KEYS

    # Known SELinux modes
    #
    # This is _the main_ or _base_ configuration for known SELinux modes. However, note that, for
    # example, a permissive mode could be set by just setting the "security" module; i.e.,
    # "security=selinux" means "enable SELinux using the permissive mode". Or even setting
    # the enforcing param to a value equal or less than 0; i.e., "security=selinux enforcing=0".
    #
    # Additionally, removing the "security" from the kernel params does not mean to use none
    # security module. Instead, it just fallback to the kernel configuration at the compile time,
    # which in SUSE is to use AppArmor according to the CONFIG_LSM variable. So, it could be said
    # that dropping all mode param to disabling SELinux is safe enough.
    #
    # To know more, please visit the LSM Usage documentation at
    # https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html
    # and/or grep for CONFIG_LSM in /boot/config-*
    MODES = {
      disabled: {
        # TRANSLATORS: the name for the disabled SELinux mode
        name: N_("Disabled"),
        options: { "security" => :missing, "selinux" => :missing, "enforcing" => :missing },
      },
      permissive: {
        # TRANSLATORS: the name for the permissive SELinux mode
        name: N_("Permissive"),
        options: { "security" => "selinux", "selinux" => "1", "enforcing" => :missing }
      },
      enforcing: {
        # TRANSLATORS: the name for the enforcing SELinux mode
        name: N_("Enforcing"),
        options: { "security" => "selinux", "selinux" => "1", "enforcing" => "1" }
      }
    }.freeze
    private_constant :MODES

    # Returns the options for the requested mode, if exists
    #
    # @param mode_id [String, Symbol] the mode identifier
    # @return [Hash, nil] options for matched mode or nil if none
    def find_mode_options(mode_id)
      id = mode_id.to_sym

      MODES[id] && MODES[id][:options]
    end

    # Proposes a mode based on `selinux_mode` value set in the control file
    def propose_mode
      mode_key = Yast::ProductFeatures.GetFeature("globals", "selinux_mode").to_sym

      log.info "Proposing the `#{mode_key}` SELinux mode"
      self.mode = mode_key
      save
    end

    # Returns the configured SELinux mode according to params in kernel command line
    #
    # @see #mode_from_kernel_params
    #
    # @return [Symbol] the mode identifier
    def configured_mode
      options = mode_from_kernel_params

      return :disabled if options.empty?

      security_module = options["security"]
      module_disabled = options["selinux"].to_i <= 0
      enforcing_mode  = options["enforcing"].to_i > 0

      return :disabled if security_module != "selinux" || module_disabled
      return :permissive unless enforcing_mode

      :enforcing
    end

    # Returns the SELinux configuration based on options set in the kernel command line
    #
    # @return [Symbol] the mode identifier
    def mode_from_kernel_params
      options = Hash[*MODE_KEYS.flat_map { |key| [key, read_param(key)] }]
      options.filter { |_, value| value != :missing }
    end

    # Convenience method to read a value from kernel parameters
    #
    # @see Yast::Bootloader#kernel_param
    def read_param(key)
      Yast::Bootloader.kernel_param(:common, key.to_s)
    end
  end
end
