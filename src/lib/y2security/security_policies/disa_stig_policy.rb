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
require "y2security/security_policies/policy"
require "y2security/security_policies/action"
require "y2security/security_policies/scopes"
require "y2security/security_policies/issue"
require "y2network/startmode"
require "y2network/connection_config/wireless"
require "bootloader/grub2base"

module Y2Security
  module SecurityPolicies
    # DISA STIG Security Policy
    class DisaStigPolicy < Policy
      include Yast::I18n

      # @see Policy
      def initialize
        textdomain "security"

        super(:disa_stig, _("Defense Information Systems Agency STIG"), ["scap-security-guide"])
      end

    private

      # @see Policy
      def issues_for(scope)
        case scope
        when Scopes::Network
          network_issues(scope.config)
        when Scopes::Storage
          storage_issues(scope.devicegraph)
        when Scopes::Firewall
          firewall_issues(scope.security_settings)
        when Scopes::Bootloader
          bootloader_issues(scope.bootloader)
        else
          []
        end
      end

      # Returns the issues in the network configuration
      #
      # * Wireless devices are not supported
      #
      # @return [Array<Issue>]
      def network_issues(config)
        conns = find_wireless_connections(config)
        return [] if conns.empty?

        conns.each_with_object([]) do |conn, all|
          message = format(_("Wireless connections are not allowed: %s"), conn.name)
          action = Action.new(_(format("disable %s device", conn.name))) do
            conn = config.connections.by_name(conn.name)
            conn.startmode = Y2Network::Startmode.create("off")
            config.add_or_update_connection_config(conn)
          end
          all << Issue.new(message, action)
        end
      end

      # Returns wireless connections which are not disabled
      #
      # @return [Array<Y2Network::ConnectionConfig::Wireless]
      def find_wireless_connections(config)
        return [] if config.nil?

        config.connections.select do |conn|
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
      # @return [Array<Issue>]
      def storage_issues(devicegraph)
        plain_filesystems = devicegraph.filesystems.select do |fs|
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
      # @return [Array<Issue>]
      def firewall_issues(security_settings)
        return [] if !!security_settings&.enable_firewall

        [
          Issue.new(
            _("Firewall is not enabled"),
            Action.new(_("enable the firewall")) do
              security_settings.enable_firewall!
            end
          )
        ]
      end

      # Returns the issues in the bootloader proposal
      #
      # * Bootloader password must be set
      # * Bootloader menu editing must be set as restricted
      #
      # @return [Array<Issue>]
      def bootloader_issues(bootloader)
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
