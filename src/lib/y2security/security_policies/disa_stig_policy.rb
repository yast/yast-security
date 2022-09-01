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
    # DISA STIG Security Policy.
    # DISA = US Defense Information Systems Agency
    # STIG = Security Technical Implementation Guides
    class DisaStigPolicy < Policy
      include Yast::I18n

      # @see Policy
      def initialize
        textdomain "security"

        # TRANSLATORS: This is a security policy name.
        #   "Defense Information Systems Agency" is from the USA, https://disa.mil/
        #   STIG = Security Technical Implementation Guides
        super(:disa_stig, _("Defense Information Systems Agency STIG"), ["scap-security-guide"])
      end

    private

      # @see Policy
      def issues_for(scope)
        case scope
        when Scopes::Network
          network_issues(scope)
        when Scopes::Storage
          storage_issues(scope)
        when Scopes::Firewall
          firewall_issues(scope)
        when Scopes::Bootloader
          bootloader_issues(scope)
        else
          []
        end
      end

      # Returns the issues in the network configuration
      #
      # Rules:
      #   * Deactivate Wireless Network Interfaces (SLES-15-010380).
      #
      # @param scope [Scopes::Network]
      # @return [Array<Issue>]
      def network_issues(scope)
        config = scope.config
        conns = find_wireless_connections(config)

        conns.each_with_object([]) do |conn, all|
          message = format(_("Wireless network interfaces must be deactivated: %s"), conn.name)
          action = Action.new(_(format("disable %s device", conn.name))) do
            conn = config.connections.by_name(conn.name)
            conn.startmode = Y2Network::Startmode.create("off")
            config.add_or_update_connection_config(conn)
          end
          all << Issue.new(message, action: action, scope: scope)
        end
      end

      # Returns wireless connections which are not disabled
      #
      # @return [Array<Y2Network::ConnectionConfig::Wireless>]
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

      # List of mount points that should exist
      SEPARATE_MOUNT_POINTS = ["/home", "/var"].freeze
      private_constant :SEPARATE_MOUNT_POINTS

      # Returns the issues in the partitioning proposal
      #
      # Rules:
      #   * All file systems are encrypted (except /boot/efi) (SLES-15-010330).
      #   * The system has a separate mount point for /home (SLES-15-040200).
      #   * The system has a separate mount point for /var (SLES-15-040210).
      #
      # @param scope [Scopes::Storage]
      # @return [Array<Issue>]
      def storage_issues(scope)
        [missing_encryptions_issue(scope), missing_mount_points_issue(scope)].compact
      end

      # Issue for missing encryption in mounted filesystems
      #
      # @param scope [Scopes::Storage]
      # @return [Issue, nil] nil if no missing encryption
      def missing_encryptions_issue(scope)
        blk_filesystems = blk_filesystems_with_missing_encryption(scope.devicegraph)
        paths = blk_filesystems.map(&:mount_path).uniq.sort

        return nil if paths.none?

        Issue.new(
          format(_("The following file systems are not encrypted: %s"), paths.join(", ")),
          scope: scope
        )
      end

      # Issue for separate mount points
      #
      # @param scope [Scopes::Storage]
      # @return [Issue, nil] nil if no missing separate mount points
      def missing_mount_points_issue(scope)
        paths = missing_mount_paths(scope.devicegraph).uniq.sort

        return nil if paths.none?

        Issue.new(
          format(_("There must be a separate mount point for: %s"), paths.join(", ")),
          scope: scope
        )
      end

      def blk_filesystems_with_missing_encryption(devicegraph)
        devicegraph.blk_filesystems.select { |f| missing_encryption?(f) }
      end

      def missing_encryption?(blk_filesystem)
        return false if blk_filesystem.encrypted? || blk_filesystem.mount_point.nil?

        !PLAIN_MOUNT_POINTS.include?(blk_filesystem.mount_path)
      end

      def missing_mount_paths(devicegraph)
        mount_paths = devicegraph.mount_points.map(&:path)

        SEPARATE_MOUNT_POINTS - mount_paths
      end

      # Returns the issues in the firewall proposal
      #
      # Rules:
      #   * Verify firewalld is enabled (SLES-15-010220).
      #
      # @param scope [Scopes::Firewall]
      # @return [Array<Issue>]
      def firewall_issues(scope)
        security_settings = scope.security_settings

        return [] if !!security_settings&.enable_firewall

        action = Action.new(_("enable the firewall")) do
          security_settings.enable_firewall!
        end

        [Issue.new(_("Firewall is not enabled"), action: action, scope: scope)]
      end

      # Returns the issues in the bootloader proposal
      #
      # Rules:
      #   * A bootloader password for grub2 must be configured and menu editing is restricted (UEFI)
      #    (SLES-15-010200).
      #
      # @param scope [Scopes::Bootloader]
      # @return [Array<Issue>]
      def bootloader_issues(scope)
        bootloader = scope.bootloader
        issues = []
        # When there is no Bootloader selected then the user will be in charge of configuring it
        # himself therefore we will not add any issue there. (e.g. Bootloader::NoneBootloader)
        return issues unless bootloader.is_a?(Bootloader::Grub2Base)

        password = bootloader.password
        unless password&.used?
          issues << Issue.new(_("Bootloader password must be set"), scope: scope)
        end

        if !password || password.unrestricted
          issues << Issue.new(_("Bootloader menu editing must be set as restricted"), scope: scope)
        end

        issues
      end
    end
  end
end
