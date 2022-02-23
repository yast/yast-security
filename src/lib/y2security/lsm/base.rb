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
require "abstract_method"

Yast.import "Arch"
Yast.import "ProductFeatures"
Yast.import "Stage"
Yast.import "Bootloader"

module Y2Security
  module LSM
    # Base class for representing and Linux Security Module configuration
    class Base
      include Yast::Logger
      include Yast::I18n

      # Constructor
      def initialize
        textdomain "security"
      end

      MINOR_MODULES = ["integrity"].freeze

      # @return [Symbol] Linux Security Module id
      abstract_method :id
      # @return [String] Linux Security Module label
      abstract_method :label

      # @return [Boolean] whether the LSM can be selected during the installation or not
      attr_accessor :selectable
      # @return [Boolean] whether the LSM can be configured during the installation or not
      attr_accessor :configurable

      # Known keys for selecting a specific Linux Security Module via kernel command line
      KERNEL_OPTIONS = ["security", "lsm"].freeze
      private_constant :KERNEL_OPTIONS

      # Returns all known keys for selecting a specific Linux Security Module via the kernel
      # command line
      #
      # @return [Array<String>]
      def kernel_options
        KERNEL_OPTIONS + [id.to_s]
      end

      # @return  [Hash<String, String>] options for selecting the LSM to be activated via kernel
      #   params
      def kernel_params
        { "lsm" => (MINOR_MODULES + [id.to_s]).join(",") }
      end

      # Returns the values for the Linux Security Module settings from the product features
      #
      # @return [Hash{Symbol => Object}] e.g., { selected: :selinux, selinux: SelinuxConfig.new }
      #   a hash holding the LSM options defined in the control file;
      #   an empty object if no settings are defined
      def product_feature_settings
        return @product_feature_settings unless @product_feature_settings.nil?

        settings = Yast::ProductFeatures.GetFeature("globals", "lsm") || {}
        settings = settings.empty? ? {} : settings.fetch(id.to_s, {})
        settings.transform_keys!(&:to_sym)

        @product_feature_settings = settings
      end

      # Returns needed patterns defined in the product features
      #
      # @return [Array<Sring>] collection of defined patterns in product features to have the
      #                        selected Linux Security Module working as expected
      def needed_patterns
        @needed_patterns ||= product_feature_settings[:patterns].to_s.split
      end

      # Whether the Module configuration can be changed
      #
      # @return [Boolean] false if running on Windows Subsystem for Linux (WSL);
      #                   the value of 'configurable' LSM specific module settings in the control
      #                   file if running in initial stage (false if value is not present);
      #                   always true when running in an installed system
      def configurable?
        return @configurable unless @configurable.nil?
        return false if Yast::Arch.is_wsl
        return true unless Yast::Stage.initial

        @configurable = product_feature_settings.fetch(:configurable, false)
      end

      # Whether the Module can be selected to be activated
      #
      # @return [Boolean] false if running on Windows Subsystem for Linux (WSL);
      #                   the value of 'selectable' LSM specific module settings in the control
      #                   file if running in initial stage (false if value is not present);
      #                   always true when running in an installed system
      def selectable?
        return @selectable unless @selectable.nil?
        return false if Yast::Arch.is_wsl
        return true unless Yast::Stage.initial

        @selectable = product_feature_settings.fetch(:selectable, true)
      end

      # Sets the needed patterns according to the given value
      #
      # @param value [String]
      def patterns=(value)
        @needed_patterns = value.split(",") if value
      end

      # Reads the configuration for the selected Linux Security Module
      #
      # @return [Boolean] whether the configuration was read or not;
      def read
        true
      end

      # Modify the bootloader kernel parameters enabling the selected Linux Security Module
      #
      # @return [Boolean] true if running in installation
      #                   the Yast::Bootloader#Write return value otherwise
      def save
        log.info("Modifying Bootlooader kernel params using #{kernel_params}")
        Yast::Bootloader.modify_kernel_params(kernel_params)

        # in insts-sys bootloader write is done by bootloader_finish client
        return true if Yast::Stage.initial

        log.info("Saving Bootloader configuration")
        Yast::Bootloader.Write
      end

      # Resets kernel params by setting all known {#kernel_options} to :missing value
      #
      # Useful for not having leftovers when changing from one LSM to another.
      #
      # @see Yast::Bootloader#modify_kernel_params
      # @see Y2Security::LSM::Config#save
      def reset_kernel_params
        kernel_params = kernel_options.each_with_object({}) { |o, r| r[o] = :missing }
        Yast::Bootloader.modify_kernel_params(kernel_params)
      end
    end
  end
end
