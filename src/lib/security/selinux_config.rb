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

    # @return [Security::SelinuxConfig::Mode] the last set mode, which can be differrent to the
    #   {#running_mode} and {#configured_mode}. A call to {#save} is needed to make it the
    #   {#configured_mode} for the next boot.
    attr_reader :mode

    # Constructor
    def initialize
      @mode = initial_mode
    end

    # Returns the initial SELinux mode
    #
    # It can be the proposed one if running in an installation or the configured mode for a
    # running system
    #
    # @return [Security::SelinuxConfig::Mode]
    def initial_mode
      return @initial_mode if @initial_mode

      propose! if Yast::Mode.installation

      @initial_mode = configured_mode
    end

    # Returns the mode applied in the running system
    #
    # @note the system can be booted with a different SELinux mode that the configured one. To
    #  know the running mode getenforce tool is used.
    #
    # @return [Mode] running SELinux mode if command executed successfully; :disabled otherwise
    def running_mode
      id = Yast::Execute.locally!(GETENFORCE_PATH, stdout: :capture).chomp.downcase.to_sym
      Mode.find(id)
    rescue Cheetah::ExecutionFailed => e
      log.info(e.message)

      Mode.find(:disabled)
    end

    # Returns a collection holding all known SELinux modes
    #
    # @return [Array<Security::SelinuxConfig::Mode>] a collection of knwon SELinux modes
    def modes
      Mode.all
    end

    # Set the mode to given value
    #
    # @note using nil means to set SELinux mode as disabled.
    #
    # @param id [String, Symbol, nil] a SELinux mode identifier
    # @return [Mode, nil] found SelinuxConfig::Mode by given id; nil if none
    def mode=(id)
      @mode = Mode.find(id)
    end

    # Set current mode options as kernel parameters for the next boot
    #
    # @note it does not write the changes when running in installation mode, where only sets the
    #   kernel params in memory, since the Yast::Bootloader.Write will be performed at the end of
    #   installation.
    #
    # @see Yast::Bootloader#modify_kernel_params
    #
    # @return [Boolean] false if mode is not set or nothing changed; true otherwise
    def save
      return false if mode.nil?

      changed = Yast::Bootloader.modify_kernel_params(**mode.options)
      changed = Yast::Bootloader.Write if changed && !Yast::Mode.installation
      changed
    end

    private

    # Path to the SELinux getenforce command
    GETENFORCE_PATH = "/usr/sbin/getenforce".freeze
    private_constant :GETENFORCE_PATH

    # Proposes a mode based on `selinux_mode` value set in the control file
    #
    # If mode is found, it calls #save for setting it.
    #
    # @return [Mode] the configured SELinux mode after trying the proposal
    def propose!
      id = Yast::ProductFeatures.GetFeature("globals", "selinux_mode").to_sym

      if Mode.find(id)
        log.info "Proposing the `#{id}` SELinux mode"
        self.mode = id
        save
      else
        log.info "Unknown `#{id}` SELinux mode. Skipping the proposal."
      end

      self.mode
    end

    # Returns the configured SELinux mode according to params in kernel command line
    #
    # @see #mode_from_kernel_params
    #
    # @return [Symbol] the mode identifier
    def configured_mode
      Mode.match(mode_from_kernel_params)
    end

    # Returns the SELinux configuration based on options set in the kernel command line
    #
    # @return [Symbol] the mode identifier
    def mode_from_kernel_params
      params = Mode.keys.flat_map do |key|
        value = Array(read_param(key)).last
        next if value == :missing

        [key, value]
      end

      Hash[*params.compact]
    end

    # Convenience method to read a value from kernel parameters
    #
    # @see Yast::Bootloader#kernel_param
    def read_param(key)
      Yast::Bootloader.kernel_param(:common, key.to_s)
    end

    # Model that represents a SELinux mode
    class Mode
      extend Yast::I18n
      include Yast::I18n

      # @return [Symbol] the id representing the mode
      attr_reader :id
      alias_method :to_sym, :id

      # @return [String] the human readable name to represent the mode
      attr_reader :name
      alias_method :to_human_string, :name

      # @return [Hash{String=><String, :missing>}] options for setting the mode via kernel params
      attr_reader :options

      # Returns all known SELinux modes
      #
      # @return [Array<Mode>]
      def self.all
        ALL.dup
      end

      # Returns all known keys for setting a SELinux mode via kernel command line
      #
      # @return [Array<String>]
      def self.keys
        OPTIONS_KEYS
      end

      # Finds a SELinux mode by its id
      #
      # @return [Mode, nil] found mode or nil if given mode id does not exists
      def self.find(id)
        ALL.find { |mode| mode.id == id.to_sym }
      end

      # Finds the SELinux mode which fits better to given options
      #
      # @return [Mode] proper mode according to values of given options
      def self.match(options)
        return find(:disabled) if options.empty?

        security_module = options["security"]
        module_disabled = options["selinux"].to_i <= 0
        enforcing_mode  = options["enforcing"].to_i > 0

        return find(:disabled) if security_module != "selinux" || module_disabled
        return find(:permissive) unless enforcing_mode

        find(:enforcing)
      end

      # Constructor
      #
      # Intended to be used internally by the class
      #
      # @param id [String, Symbol] if of the mode
      # @param name [String] the mode name, a string marked for translation
      # @param enable [Boolean] wether the mode will enable SELinux
      # @param enforcing [Boolean] if SELinux should be run enforcing or not
      def initialize(id, name, enable, enforcing)
        textdomain "security"

        @id = id.to_sym
        @name = _(name)
        @options = {
          "security"  => enable    ? "selinux" : :missing,
          "selinux"   => enable    ? "1"       : :missing,
          "enforcing" => enforcing ? "1"       : :missing
        }
      end

      private

      # All known SELinux modes
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
      ALL = [
        new(:disabled,   N_("Disabled"),   false, false),
        new(:permissive, N_("Permissive"), true,  false),
        new(:enforcing,  N_("Enforcing"),  true,  true),
      ].freeze
      private_constant :ALL

      # Known keys for setting a SELinux mode via kernel command line
      OPTIONS_KEYS = ["security", "selinux", "enforcing"]
      private_constant :OPTIONS_KEYS
    end
  end
end
