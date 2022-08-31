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

module Y2Security
  module SecurityPolicies
    module Scopes
      # Scope for firewall checks
      class Firewall
        include Yast::Logger

        # Security settings to use with this scope
        #
        # @return [Installation::SecuritySettings, nil] nil if yast2-installation is not available
        attr_reader :security_settings

        # Constructor
        #
        # @param security_settings [Installation::SecuritySettings] Settings to use with this scope.
        #   If no settings are given, then current YaST settings are used.
        def initialize(security_settings: nil)
          @security_settings = security_settings || default_security_settings
        end

      private

        # Default security settings to use
        #
        # @return [Installation::SecuritySettings, nil] nil if yast2-installation is not available
        def default_security_settings
          ensure_security_settings { ::Installation::SecuritySettings.instance }
        end

        # Ensures that security settings is loaded and runs the given block
        #
        # FIXME: avoid a cyclic dependency with yast2-installation
        #
        # The package yast2-installation has yast2-security as dependency, so yast2-security does
        # not require yast2-installation at RPM level to avoid cyclic dependencies. Note that
        # yast2-installation is always included in the installation image, but it could be missing
        # at building time. And missing yast2-installation in a running system should not be
        # relevant because the policies are only checked during the installation.
        def ensure_security_settings
          require "installation/security_settings"
          yield
        rescue LoadError
          log.warn("Security settings cannot be loaded. Make sure yast2-installation is installed.")
          nil
        end
      end
    end
  end
end
