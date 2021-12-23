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

require "y2security/lsm/config"
require "y2security/autoinst_profile"

module Y2Security
  module Autoinst
    # This class is responsible of reading the Linux Security Module configuration declared in
    # the AutoYaST profile
    class LSMConfigReader
      # @return [AutoinstProfile::LSMSection]
      attr_reader :section
      # @return [AutoinstProfile::SelinuxSection, AutoinstProfile::ApparmorSection, nil]
      attr_reader :module_section

      # Constructor
      #
      # @param section [AutoinstProfile::LSMSection]
      def initialize(section)
        @section = section
      end

      # Reads the Linux Security Module configuration defined in the profile modifying it
      # accordingly
      def read
        return unless section

        config.configurable = section.configurable
        config.select(section.select) if section.select
        configure_supported_modules
      end

    private

      def configure_supported_modules
        [:selinux, :apparmor].each do |id|
          lsm_module = config.public_send(id)
          @module_section = section.public_send(id)
          next unless module_section

          assign(lsm_module, :mode) if id == :selinux
          assign(lsm_module, :configurable)
          assign(lsm_module, :selectable)
          assign(lsm_module, :patterns)
        end
      end

      def assign(lsm_module, option)
        value = module_section.public_send(option)
        lsm_module.public_send("#{option}=", value) unless value.nil?
      end

      def config
        Y2Security::LSM::Config.instance
      end
    end
  end
end
