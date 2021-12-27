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
require "y2security/lsm/base"
require "y2security/lsm/app_armor"
require "y2security/lsm/none"
require "y2security/lsm/selinux"

Yast.import "Stage"
Yast.import "ProductFeatures"

module Y2Security
  module LSM
    # This class allows to check and select one of the supported Linux Security Modules (LSM)
    class Config
      include Yast::Logger
      include Singleton

      RUNNING_PATH = "/sys/kernel/security/lsm".freeze
      private_constant :RUNNING_PATH
      SUPPORTED = [None, Selinux, AppArmor].freeze
      private_constant :SUPPORTED

      # @return [None, AppArmor,Selinux, nil] selected module if any or nil otherwise
      attr_accessor :selected
      # @return [Boolean] Whether LSM can be configured by the user or not
      attr_accessor :configurable

      def initialize
        supported.each { |m| self.class.send(:define_method, m.id) { m } }
      end

      # Select the LSM to be used based in the one defined in the control file using apparmor as
      # fallback in case that no one is selected
      def propose_default
        log.info("The settings are #{product_feature_settings.inspect}")
        selected = product_feature_settings.fetch(:select, "apparmor")

        select(selected)
      end

      # Select the module with the given id when it is selectable.
      #
      # @param id [String,Symbol] LSM id to be selected
      def select(id)
        @selected = selectable.find { |m| m.id == id.to_sym }
        log.info @selected ? "Selected LSM with id: #{id}" : "No LSM selected with id: #{id}"
        @selected
      end

      # Convenience method to obtain a list of the supported and selectable modules
      #
      # @return [Array<Y2Security::LSM::Base>] array of supported and selectable LSMs
      def selectable
        supported.select(&:selectable?)
      end

      # Returns the needed patterns for the selected LSM or an empty array if no one is selected
      #
      # @return [Array<Sting>]
      def needed_patterns
        return [] unless selected

        selected.needed_patterns
      end

      # Convenience method to save the configuration for the selected LSM
      #
      # @note: all LSM kernel options are reset before save the selected one.
      #   See {Y2Security::LSM::Base#reset_kernel_params}
      #
      # @return [Boolean] true if a module is selected and its config is successfully saved;
      #   false otherwise
      def save
        return false unless selected

        supported.each(&:reset_kernel_params)
        selected.save
      end

      # Obtains the supported and active Linux Security Major Module from the running system
      #
      # @return [Y2Security::LSM::Base]
      def from_system
        active.first
      end

      # In a running system it reads which Linux Security Module is active and its configuration
      #
      # @note: during the installation there is **no** active LSM
      #
      # @return [Boolean] false during installation;
      #                   whether the configuration was read or not otherwise.
      def read
        return false unless Yast::Stage.normal

        @selected = from_system
        return false unless @selected

        @selected.read
      end

      # Return an array with the supported and active Linux Security Major Modules
      #
      # @return [Array<Y2Security::LSM::Base>]
      def active
        return [] unless Yast::Stage.normal

        modules = Yast::SCR.Read(Yast.path(".target.string"), RUNNING_PATH)
        modules.split(",").each_with_object([]) do |name, result|
          supported_module = supported.find { |m| m.id.to_s == name }
          result << supported_module if supported_module
        end
      end

      # Returns whether the LSM is configurable during installation or not based in the control file
      # declaration. It returns false in case it is WSL
      #
      # @return [Boolean] false when running in a WSL
      #                   whether LSM is configurable during the installation or not
      def configurable?
        return @configurable unless @configurable.nil?
        return false if Yast::Arch.is_wsl

        @configurable = product_feature_settings[:configurable] || false
      end

      # Returns the values for the LSM setting from the product features
      #
      # @return [Hash{Symbol => Object}] e.g., { selinux: { "selectable" => true } }
      #   a hash holding the LSM options defined in the control file;
      #   an empty object if no settings are defined
      def product_feature_settings
        return @product_feature_settings unless @product_feature_settings.nil?

        settings = Yast::ProductFeatures.GetFeature("globals", "lsm")
        settings = {} if settings.empty?
        settings.transform_keys!(&:to_sym)

        @product_feature_settings = settings
      end

      # Obtains and memoize all the Linux Security Supported Modules
      #
      # @return [Array<Y2Security::LSM::Base>]
      def supported
        @supported ||= SUPPORTED.map(&:new)
      end

      # Resets the memoized configuration
      def reset
        @selected = nil
        @supported = nil
        @product_feature_settings = nil
        @configurable = nil
      end
    end
  end
end
