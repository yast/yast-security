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
require "y2storage/storage_manager"
require "cfa/selinux"
require "y2security/lsm/base"

Yast.import "Bootloader"
Yast.import "Stage"

module Y2Security
  module LSM
    # Class for handling SELinux kernel params
    #
    # @example Querying the currently configured SELinux mode
    #   selinux = Selinux.new
    #   mode = selinux.mode
    #   mode.id #=> :permissive
    #   mode.name #=> "Permisive"
    #   mode.options ~=> { "lsm" => "selinux", "selinux" => "1", "enforcing" => :missing }
    #
    # @example Querying the currently running SELinux mode
    #   selinux= Selinux.new
    #   mode = selinux.running_mode
    #   mode.id #=> :enforcing
    #   mode.name #=> "Enforcing"
    #   mode.options ~=> { "lsm" => "selinux", "selinux" => "1", "enforcing" => "1" }
    #
    # @example Querying the SELinux mode set in the config file
    #   selinux= Selinux.new
    #   mode = selinux.configured_mode
    #   mode.id #=> :permissive
    #   mode.name #=> "Permisive"
    #   mode.options ~=> { "lsm" => "selinux", "selinux" => "1", "enforcing" => :missing }
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
    class Selinux < Base
      def initialize
        super
        textdomain "security"
      end

      # @see Base#id
      def id
        :selinux
      end

      # @see Base#label
      def label
        _("SELinux")
      end

      # Forces the read of the SELinux mode
      #
      # @see Base#read
      #
      # @return [Boolean]
      def read
        mode

        true
      end

      # The current set mode
      #
      # @note initially, it will be set to the {#proposed_mode}  or
      # {#configured_mode}, as applicable. When SELinux is enabled
      # but the mode was set through neither, a boot kernel param nor configuration
      # file, the "permissive" mode is assumed.
      #
      # @note a #{save} call is needed to make it the SELinux mode starting with the next boot.
      #
      # @return [Selinux::Mode] the current set mode, which initially can be the {#proposed_mode}
      # or the {#configured_mode} as applicable. A {#save} call is needed to make it
      # the for the next boot.
      def mode
        @mode ||= make_proposal || configured_mode || Mode.find(:permissive)
      end

      # Returns the configured mode in the SELinux config file
      #
      # @return [Mode, nil] the SELinux mode set in the config file; nil if unknown or not set
      def configured_mode
        # selinux is disabled on cmdline, but mode is set in config file. See https://bugzilla.suse.com/show_bug.cgi?id=1239717
        options = options_from_kernel_params
        return if options.empty?

        disabled_mode = options.fetch("selinux", 1).to_i <= 0
        return Mode.find(:disabled) if disabled_mode

        Mode.find(config_file.selinux)
      end

      # Returns the mode applied in the running system
      #
      # @note the system can be booted with a different SELinux mode that the configured one. To
      #  know the running mode getenforce SELinux tool is used.
      #
      # @return [Mode, nil] running SELinux mode if command executed successfully; nil otherwise
      def running_mode
        id = Yast::Execute.locally!(GETENFORCE_PATH, stdout: :capture).chomp.downcase.to_sym
        Mode.find(id)
      rescue Cheetah::ExecutionFailed => e
        log.info(e.message)

        nil
      end

      # Returns a collection holding all known SELinux modes
      #
      # @return [Array<Selinux::Mode>] a collection of known SELinux modes
      def modes
        Mode.all
      end

      # Set the mode to given value
      #
      # @note using nil means to set SELinux mode as disabled.
      #
      # @param id [Selinux::Mode, String, Symbol, nil] a SELinux mode or its identifier
      # @return [Mode] the Selinux::Mode by given id or disabled is none found or nil was given
      def mode=(id)
        found_mode = Mode.find(id)

        if found_mode.nil?
          log.error("Requested SELinux mode `#{id}` not found. Falling back to :disabled.")
          found_mode = Mode.find(:disabled)
        end

        @mode = found_mode
      end

      # @see Base#kernel_params
      def kernel_params
        mode.options
      end

      # Set current mode for the next boot
      #
      # Setting both, the boot kernel parameters and the SELinux configuration file
      #
      # @note it does not write the Bootloader changes when running in installation mode, where
      #   only sets the kernel params in memory since Yast::Bootloader.Write will be performed at
      #   the end of installation.
      #
      # @see #configurable?
      # @see Yast::Bootloader#modify_kernel_params
      # @see CFA::Selinux#save
      #
      # @return [Boolean] true if running in installation where SELinux is configurable;
      #                   false if running in installation where SELinux is not configurable;
      #                   the Yast::Bootloader#Write return value otherwise
      def save
        return false unless configurable?
        return false unless super

        log.info("Saving SELinux config file to set #{mode.id} mode")
        config_file.selinux = mode.id.to_s
        config_file.save

        if relocate_autorelabel_file?
          log.info("Detected a read-only root fs: relocating .autorelabel file")

          relocate_autorelabel_file
        end

        true
      end

    private

      # Path to the SELinux getenforce command
      GETENFORCE_PATH = "/usr/sbin/getenforce".freeze
      private_constant :GETENFORCE_PATH

      # Path to .autorelabel file in root
      ROOT_AUTORELABEL_PATH = "/.autorelabel".freeze
      private_constant :ROOT_AUTORELABEL_PATH

      # Path to .autorelabel file in /etc
      ETC_AUTORELABEL_PATH = "/etc/selinux/.autorelabel".freeze
      private_constant :ETC_AUTORELABEL_PATH

      # Path to `rm` command
      RM_COMMAND = "/usr/bin/rm".freeze
      private_constant :RM_COMMAND

      # Path to `touch` command
      TOUCH_COMMAND = "/usr/bin/touch".freeze
      private_constant :TOUCH_COMMAND

      # Returns a CFA::Selinux object for handling the config file
      #
      # @return [CFA::Selinux]
      def config_file
        @config_file ||= CFA::Selinux.load
      end

      # Sets the mode to the proposed one via selinux mode global variable in the control file
      #
      # @see #proposed_mode
      #
      # @return [Mode] disabled or found SELinux mode
      def make_proposal
        return unless Yast::Stage.initial

        proposed_mode
      end

      # Returns the proposed mode via the `selinux_mode` global variable in the control file
      #
      # @see Mode.find
      #
      # @return [Mode, nil] found SELinux mode or nil if none
      def proposed_mode
        id = product_feature_settings[:mode]
        found_mode = Mode.find(id)

        if found_mode.nil?
          log.error("Proposed SELinux mode `#{id}` not found.")

          return nil
        end

        log.info("Proposing `#{id}` SELinux mode.")
        found_mode
      end

      # Returns the SELinux configuration based on options set in the kernel command line
      #
      # @return [Symbol] the mode identifier
      def options_from_kernel_params
        params = kernel_options.flat_map do |key|
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

      # Whether the .autorelabel file should be relocated
      #
      # @see https://jira.suse.com/browse/SLE-17307
      #
      # @return [Booelan] true if root fs will mounted as read only, SELinux is not disabled,
      #                   and running in initial stage; false otherwise
      def relocate_autorelabel_file?
        mode.to_sym != :disabled && Yast::Stage.initial && read_only_root_fs?
      end

      # Relocates the .autorelabel file from #{ROOT_AUTORELABEL_PATH} to #{ETC_AUTORELABEL_PATH} by
      # removing the first and touching the latter.
      #
      # @see #save
      # @see https://jira.suse.com/browse/SLE-17307
      def relocate_autorelabel_file
        log.info("Deleting #{ROOT_AUTORELABEL_PATH} file")
        Yast::Execute.stdout.on_target!(RM_COMMAND, ROOT_AUTORELABEL_PATH)

        log.info("Touching #{ETC_AUTORELABEL_PATH} file")
        Yast::Execute.stdout.on_target!(TOUCH_COMMAND, ETC_AUTORELABEL_PATH)
      end

      # Whether the root file system will be mounted as read only
      #
      # @return [Booelan] true if "ro" is one of the root fs mount options; false otherwise
      def read_only_root_fs?
        staging_graph = Y2Storage::StorageManager.instance.staging
        root_fs = staging_graph.filesystems.find(&:root?)

        return false unless root_fs

        root_fs.mount_options.include?("ro")
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

        # Finds a SELinux mode by its id
        #
        # @param id [Mode, String, Symbol, nil]
        # @return [Mode, nil] found mode or nil if given mode id does not exists
        def self.find(id)
          ALL.find { |mode| mode.id == id&.to_sym }
        end

        # Constructor
        #
        # Intended to be used internally by the class
        #
        # @param id [String, Symbol] id of the mode
        # @param name [String] the mode name, a string marked for translation
        # @param disable [Boolean] whether the mode will be disabled or not
        def initialize(id, name, disable)
          textdomain "security"

          @id = id.to_sym
          @name = name
          @options = {
            "security" => "selinux",
            "selinux"  => disable ? "0" : "1"
          }
        end

        # Return the human readable name to represent the mode
        #
        # @return [String]
        def name
          _(@name)
        end
        alias_method :to_human_string, :name

        # All known SELinux modes
        #
        # This is _the main_ or _base_ configuration for known SELinux modes. However, note that,
        # mode is no longer driver by kernel command line, but by selinux config file.
        # For more see https://jira.suse.com/browse/PED-12400
        #
        # Additionally, removing the "lsm" from the kernel params does not mean to use none
        # LSM module. Instead, it just fallback to the kernel configuration at the compile
        # time, which in SUSE is to use AppArmor according to the CONFIG_LSM variable. So, it
        # could be said that dropping all mode param to disabling SELinux is safe enough.
        #
        # To know more, please visit the LSM Usage documentation at
        # https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html
        # and/or grep for CONFIG_LSM in /boot/config-*
        ALL = [
          new(:disabled,   N_("Disabled"),   true),
          new(:permissive, N_("Permissive"), false),
          new(:enforcing,  N_("Enforcing"),  false)
        ].freeze
        private_constant :ALL
      end
    end
  end
end
