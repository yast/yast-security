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

module Y2Security
  module LSM
    # This class allows to check and select one of the supported Linux Security Modules (LSM)
    class Config
      include Yast::Logger
      RUNNING_PATH = "/sys/kernel/security/lsm".freeze
      SUPPORTED = [None, Selinux, AppArmor].freeze

      # @return [AppArmor,Selinux, nil] selected module
      attr_accessor :selected

      # Constructor
      #
      # @param selected [Y2Security::LSM::Base]
      def initialize(selected = nil)
        @selected = selected
      end

      # Select the module with the given id when it is selectable.
      #
      # @param id [String,Symbol] LSM id to be selected
      def select(id)
        @selected = selectable.find { |m| m.id == id.to_sym }
        log.info @selected ? "Selected LSM with id: #{id}" : "No LSM selected with id: #{id}"
        @selected
      end

      # Convenience method to obtain a list of the supported modules
      #
      # @return [Array<Y2Security::LSM::Base] array of supported LSMs
      def supported
        self.class.supported
      end

      # Convenience method to obtain a list of the supported and selectable modules
      #
      # @return [Array<Y2Security::LSM::Base] array of supported and selectable LSMs
      def selectable
        supported.select(&:selectable?)
      end

      # Convenience method to save the configuration for the selected LSM
      def save
        return false unless selected

        selected.save
      end

      class << self
        # Obtains the supported and active Linux Security Major Module from the running system
        #
        # @return [Y2Security::LSM::Base]
        def from_system
          active.first
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

        # Obtains and memoize all the Linux Security Supported Modules
        #
        # @return [Array<Y2Security::LSM::Base>]
        def supported
          @supported ||= SUPPORTED.map(&:new)
        end

        # Resets the memoized configuration
        def reset
          @supported = nil
        end
      end
    end
  end
end
