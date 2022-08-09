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
require "y2security/security_policy_validator"
require "y2security/security_policy_issues"
require "y2network/connection_config/wireless"

Yast.import "Lan"

module Y2Security
  # Validator for the STIG security policy
  class StigValidator < SecurityPolicyValidator
    include Yast::I18n

    # Returns the issues found for the given scope
    #
    # @param scope [Symbol] Scope to validate (:network, :storage, :bootloader, etc.)
    def issues(scope)
      all_issues = [:firewall, :network, :storage].reduce([]) do |all, scope|
        all += send("#{scope}_issues")
      end
      SecurityPolicyIssues.new(all_issues)
    end

  private

    # Returns the issues in the network configuration
    #
    # * Wireless devices are not supported
    #
    # @return [Array<Y2Issues::Issue>]
    def network_issues
      return [] if Yast::Lan.yast_config.nil?

      wireless = Yast::Lan.yast_config.connections.select do |conn|
        conn.is_a?(Y2Network::ConnectionConfig::Wireless) &&
          conn.startmode&.name != "off"
      end
      return [] if wireless.empty?

      [
        Y2Issues::Issue.new(
          format(
            _("Wireless connections are not allowed: %s"),
            wireless.map(&:name).join(", ")
          ),
          severity: :error, location: "proposal:network"
        )
      ]
    end

    # List of mount points that are not expected to be encrypted
    PLAIN_MOUNT_POINTS = ["/boot/efi"].freeze
    private_constant :PLAIN_MOUNT_POINTS

    # Returns the issues in the partitioning proposal
    #
    # * Full disk encryption is required
    #
    # @return [Array<Y2Issues::Issue>]
    def storage_issues
      staging = Y2Storage::StorageManager.instance.staging
      plain_filesystems = staging.filesystems.select do |fs|
        mp = fs.mount_point
        next if mp.nil? || PLAIN_MOUNT_POINTS.include?(mp.path)

        plain_filesystem?(fs)
      end

      return [] if plain_filesystems.empty?

      mount_paths = plain_filesystems.map(&:mount_path)
      [
        Y2Issues::Issue.new(
          format(
            # TRANSLATORS: %s is a list of mount points
            _("The following file systems are not encrypted: %s"), mount_paths.join(", ")
          ),
          severity: :error, location: "proposal:storage"
        )
      ]
    end

    # Determines whether the file system is encrypted or plain
    #
    # A file system might not be encrypted by itself, but belong to
    # something that it is (like a LVM volume group).
    #
    # @param filesystem [Y2Storage::Filesystems::Base] Determines whether a file system is encrypted
    #   or not
    # @return [Boolean] true if the file system is plain; false otherwise
    def plain_filesystem?(filesystem)
      filesystem.ancestors.none? { |d| d.respond_to?(:encrypted?) && d.encrypted? }
    end

    # Returns the issues in the firewall proposal
    #
    # * Firewall must be enabled
    #
    # @return [Array<Y2Issues::Issue>]
    def firewall_issues
      return [] if !!security_settings.enable_firewall

      [
        Y2Issues::Issue.new(
          _("Firewall is not enabled"),
          severity: :error, location: "proposal:firewall"
        )
      ]
    end

    # Convenience method to obtain an Installation::SecuritySettings instance
    #
    # @return [Installation::SecuritySettings]
    def security_settings
      Installation::SecuritySettings.instance
    end
  end
end
