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

module Y2Security
  # Class for handling SELinux kernel params
  #
  # @example Querying the currently configured SELinux mode
  #   selinux = Selinux.new
  #   mode = selinux.mode
  #   mode.id #=> :permissive
  #   mode.name #=> "Permisive"
  #
  # @example Querying the currently running SELinux mode
  #   selinux= Selinux.new
  #   mode = selinux.running_mode
  #   mode.id #=> :enforcing
  #   mode.name #=> "Enforcing"
  #
  # @example Enabling SELinux in Permissive mode for next boot
  #   selinux = Selinux.new
  #   selinux.mode = :permissive
  #   selinux.save #=> true
  #
  # @example Disabling SELinux for next boot
  #   selinux = Selinux.new
  #   selinux.mode = :disabled
  #   selinux.save #=> true
  #
  # @example Disabling SELinux for next boot (using nil)
  #   selinux = Selinux.new
  #   selinux.mode = nil
  #   selinux.mode.id  #=> :disabled
  #   selinux.save #=> true
  #
  # @example Trying to enable SELinux during an installation set to be configurable
  #   selinux = Selinux.new
  #   selinux.mode = :permissive
  #   selinux.save #=> true
  #
  # @example Trying to enable SELinux during an installation set to not be configurable
  #   selinux = Selinux.new
  #   selinux.mode = :permissive
  #   selinux.save #=> false
  class Selinux
    include Yast::Logger

    Yast.import "Bootloader"
    Yast.import "ProductFeatures"

    # @return [Selinux::Mode] the last set mode, which can be differrent to the
    #   {#running_mode} and {#configured_mode}. A call to {#save} is needed to make it the
    #   {#configured_mode} for the next boot.
    def mode
      @mode ||= make_proposal || configured_mode
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
    # @return [Array<Selinux::Mode>] a collection of known SELinux modes
    def modes
      Mode.all
    end

    # Set the mode to given value
    #
    # @see #find_mode
    def mode=(id)
      @mode = find_mode(id)
    end

    # Set current mode options as kernel parameters for the next boot
    #
    # @note it does not write the changes when running in installation mode, where only sets the
    #   kernel params in memory since Yast::Bootloader.Write will be performed at the end of
    #   installation.
    #
    # @see #configurable?
    # @see Yast::Bootloader#modify_kernel_params
    #
    # @return [Boolean] true if running in installation where selinux is configurable;
    #                   false if running in installation where selinux is not configurable;
    #                   the Yast::Bootloader#Write return value otherwise
    def save
      return false unless configurable?

      Yast::Bootloader.modify_kernel_params(mode.options)

      return true if Yast::Mode.installation

      Yast::Bootloader.Write
    end

    # Whether SELinux configuration can be changed
    #
    # @return [Boolean] always true when running in installed system;
    #                   the value of 'configurable' selinux settings in the control file when
    #                   running during installation or false if not present
    def configurable?
      return true unless Yast::Mode.installation

      product_feature_settings[:configurable] || false
    end

    private

    # Path to the SELinux getenforce command
    GETENFORCE_PATH = "/usr/sbin/getenforce".freeze
    private_constant :GETENFORCE_PATH

    # Returns the values for the SELinux setting from the product features
    #
    # @return [Hash{Symbol => String, Boolean, nil}] e.g., { mode: "enforcing", configurable: false }
    #   a hash holding the defined SELinux options in the control file;
    #   an empty object if no settings are defined
    def product_feature_settings
      @product_feature_settings unless @product_feature_settings.nil?

      settings = Yast::ProductFeatures.GetFeature("globals", "selinux")
      settings = {} if settings.empty?
      settings.transform_keys!(&:to_sym)

      @product_feature_settings = settings
    end

    # Find SELinux mode by given value
    #
    # @note using nil means to set SELinux mode as disabled.
    #
    # @param id [Selinux::Mode, String, Symbol, nil] a SELinux mode or its identifier
    # @return [Mode] the Selinux::Mode by given id or disabled is none found or nil was given
    def find_mode(id)
      found_mode = Mode.find(id)

      if found_mode.nil?
        log.info("Requested SELinux mode `#{id}` not found. Falling back to :disabled.")
        found_mode = Mode.find(:disabled)
      end

      found_mode
    end

    # Sets the mode to the proposed one via `selinux_mode` global variable in the control file
    #
    # @see #proposed_mode
    #
    # @return [Mode] disabled or found SELinux mode
    def make_proposal
      return unless Yast::Mode.installation

      proposed_mode
    end

    # Returns the proposed mode via the `selinux_mode` global variable in the control file
    #
    # @see Mode.find
    #
    # @return [Mode] disabled or found SELinux mode
    def proposed_mode
      id = product_feature_settings[:mode]

      log.info("Proposing `#{id}` SELinux mode.")

      find_mode(id)
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
      params = Mode.kernel_options.flat_map do |key|
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

      # @return [Hash{String=><String, :missing>}] options for setting the mode via kernel params
      attr_reader :options

      # Returns all known SELinux modes
      #
      # @return [Array<Mode>]
      def self.all
        ALL
      end

      # Returns all known keys for setting a SELinux mode via kernel command line
      #
      # @return [Array<String>]
      def self.kernel_options
        KERNEL_OPTIONS
      end

      # Finds a SELinux mode by its id
      #
      # @param id [Mode, String, Symbol, nil]
      # @return [Mode, nil] found mode or nil if given mode id does not exists
      def self.find(id)
        ALL.find { |mode| mode.id == id&.to_sym }
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
      # @param id [String, Symbol] id of the mode
      # @param name [String] the mode name, a string marked for translation
      # @param enable [Boolean] whether the mode will enable SELinux
      # @param enforcing [Boolean] if SELinux should be run enforcing or not
      def initialize(id, name, enable, enforcing)
        textdomain "security"

        @id = id.to_sym
        @name = name
        @options = {
          "security"  => enable    ? "selinux" : :missing,
          "selinux"   => enable    ? "1"       : :missing,
          "enforcing" => enforcing ? "1"       : :missing
        }
      end

      # Return the human readable name to represent the mode
      #
      # @return [String]
      def name
        _(@name)
      end
      alias_method :to_human_string, :name

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
      KERNEL_OPTIONS = ["security", "selinux", "enforcing"]
      private_constant :KERNEL_OPTIONS
    end
  end
end
