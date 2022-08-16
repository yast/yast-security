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
require "y2security/security_policies/validator"
require "y2security/security_policies/issue"
require "y2security/security_policies/action"
require "y2issues/list"
require "y2network/connection_config/wireless"
require "bootloader/bootloader_factory"
require "bootloader/grub2base"

Yast.import "Lan"

module Y2Security
  module SecurityPolicies
    # Validator for the STIG security policy
    class DisaStigValidator < Validator
      include Yast::I18n

      KNOWN_SCOPES = [:bootloader, :firewall, :network, :storage].freeze
      private_constant :KNOWN_SCOPES

      def initialize
        textdomain "security"
      end

      # Returns the issues found for the given scope
      #
      # @return [Y2Issues::List] List of found issues
      def validate(*scopes)
        scopes_to_validate = scopes.empty? ? KNOWN_SCOPES : KNOWN_SCOPES & scopes
        scopes_to_validate.reduce([]) do |all, scope|
          all + send("#{scope}_issues")
        end
      end

    private

      # Returns the issues in the network configuration
      #
      # * Wireless devices are not supported
      #
      # @return [Array<Y2Issues::Issue>]
      def network_issues
        conns = find_wireless_connections
        return [] if conns.empty?

        conns.each_with_object([]) do |conn, all|
          message = format(
            _("Wireless connections are not allowed: %s"), conn.name
          )
          action = Action.new(_(format("disable %s device", conn.name))) do
            yast_config = Yast::Lan.yast_config
            conn = yast_config.connections.by_name(conn.name)
            conn.startmode = Y2Network::Startmode.create("off")
            yast_config.add_or_update_connection_config(conn)
          end
          all << Issue.new(message, action)
        end
      end

      # Returns wireless connections which are not disabled
      #
      # @return [Array<Y2Network::ConnectionConfig::Wireless]
      def find_wireless_connections
        return [] if Yast::Lan.yast_config.nil?

        Yast::Lan.yast_config.connections.select do |conn|
          conn.is_a?(Y2Network::ConnectionConfig::Wireless) &&
            conn.startmode&.name != "off"
        end
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
          Issue.new(
            format(
              # TRANSLATORS: %s is a list of mount points
              _("The following file systems are not encrypted: %s"), mount_paths.join(", ")
            )
          )
        ]
      end

      # Determines whether the file system is encrypted or plain
      #
      # A file system might not be encrypted by itself, but belong to
      # something that it is (like a LVM volume group).
      #
      # @param filesystem [Y2Storage::Filesystems::Base] Determines whether a file system is
      #   encrypted or not
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
          Issue.new(
            _("Firewall is not enabled"),
            Action.new(_("enable the firewall")) do
              security_settings.enable_firewall!
            end
          )
        ]
      end

      # Convenience method to obtain an Installation::SecuritySettings instance
      #
      # @return [Installation::SecuritySettings]
      def security_settings
        # FIXME: avoid a singular dependency with yast2-installation
        require "installation/security_settings"
        ::Installation::SecuritySettings.instance
      end

      def bootloader
        ::Bootloader::BootloaderFactory.current
      end

      # Returns the issues in the bootloader proposal
      #
      # * Bootloader password must be set
      # * Bootloader menu editing must be set as restricted
      #
      # @return [Array<Y2Issues::Issue>]
      def bootloader_issues
        issues = []
        # When there is no Bootloader selected then the user will be in charge of configuring it
        # himself therefore we will not add any issue there. (e.g. Bootloader::NoneBootloader)
        return issues unless bootloader.is_a?(Bootloader::Grub2Base)

        password = bootloader.password
        unless password&.used?
          issues << Issue.new(
            _("Bootloader password must be set")
          )
        end

        if !password || password.unrestricted
          issues << Issue.new(
            _("Bootloader menu editing must be set as restricted")
          )
        end

        issues
      end
    end
  end
end
