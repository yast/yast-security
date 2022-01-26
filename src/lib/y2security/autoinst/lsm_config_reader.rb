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
require "y2security/autoinst_profile/security_section"

module Y2Security
  module Autoinst
    # This class is responsible of reading the Linux Security Module configuration declared in
    # the AutoYaST profile
    class LSMConfigReader
      # @return [AutoinstProfile::SecuritySection]
      attr_reader :section
      # Constructor
      #
      # @param section [AutoinstProfile::SecuritySection]
      def initialize(section)
        @section = section
      end

      # Reads the Linux Security Module configuration defined in the profile modifying it
      # accordingly
      def read
        return unless section.lsm_select || section.selinux_mode

        select_module
        configure_selinux if selinux?
      end

    private

      def selinux?
        return true if section.lsm_select == "selinux"

        !section.lsm_select && section.selinux_mode
      end

      def configure_selinux
        config.selinux.mode = section.selinux_mode
      end

      def select_module
        selected = selinux? ? "selinux" : section.lsm_select
        config.select(selected)
      end

      def config
        Y2Security::LSM::Config.instance
      end
    end
  end
end
