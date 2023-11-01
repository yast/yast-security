# Copyright (c) [2022] SUSE LLC
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
require "y2storage/storage_manager"
require "bootloader/bootloader_factory"

module Y2Security
  module SecurityPolicies
    # This class represents the target system configuration
    #
    # Instead of having to fetch information from several singleton classes and modules,
    # policy rules get the information they need through an instance of this class.
    # This approach has these advantages:
    #
    # * The main point is that injecting the configuration makes testing easier.
    # * Each rule decides which aspects of the configuration are relevant for them.
    #
    class TargetConfig
      include Yast::Logger

      # @return [Y2Storage::Devicegraph]
      attr_accessor :storage

      # @return [Bootloader::BootloaderFactory]
      attr_accessor :bootloader

      def initialize
        @storage = default_devicegraph
        @bootloader = default_bootloader
      end

      # @return [Y2Network::Config]
      def network
        default_network_config
      end

      # @return [Installation::SecuritySettings, nil] nil if yast2-installation is not available
      def security
        default_security_settings
      end

      # Default devicegraph
      #
      # @return [Y2Storage::Devicegraph]
      def default_devicegraph
        Y2Storage::StorageManager.instance.staging
      end

      # Default bootloader
      #
      # @return [Bootloader::BootloaderFactory]
      def default_bootloader
        ::Bootloader::BootloaderFactory.current
      end

      # Default network config
      #
      # @return [Y2Network::Config]
      def default_network_config
        Yast.import "Lan"
        Yast::Lan.yast_config
      end

      # Default security settings
      #
      # FIXME: avoid a cyclic dependency with yast2-installation
      #
      # The package yast2-installation has yast2-security as dependency, so yast2-security does
      # not require yast2-installation at RPM level to avoid cyclic dependencies. Note that
      # yast2-installation is always included in the installation image, but it could be missing
      # at building time. And missing yast2-installation in a running system should not be
      # relevant because the policies are only checked during the installation.
      #
      # @return [Installation::SecuritySettings, nil] nil if yast2-installation is not available
      def default_security_settings
        require "installation/security_settings"
        ::Installation::SecuritySettings.instance
      rescue LoadError
        log.warn("Security settings cannot be loaded. Make sure yast2-installation is installed.")
        nil
      end
    end
  end
end
