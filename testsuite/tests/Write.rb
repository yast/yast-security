# encoding: utf-8

# YaST2: Modules testsuite
#
# Description:
#   Testsuite for the security module
#
# Authors:
#   Michal Svec <msvec@suse.cz>
#
# $Id$
#
# testedfiles: Security.ycp PamSettings.ycp Pam.ycp
module Yast
  class WriteClient < Client
    def main
      Yast.include self, "testsuite.rb"

      Yast.import "Security"

      @m = {
        "CONSOLE_SHUTDOWN"                          => "halt",
        "DISPLAYMANAGER_REMOTE_ACCESS"              => "r4",
        "ENCRYPTION"                                => "md5",
        "kernel.sysrq"                              => "1",
        "FAIL_DELAY"                                => "l2",
        "GID_MAX"                                   => "l3",
        "GID_MIN"                                   => "l4",
        "DISPLAYMANAGER_SHUTDOWN"                   => "r3",
        "PASS_MAX_DAYS"                             => "l7",
        "PASS_MIN_DAYS"                             => "l9",
        "PASS_MIN_LEN"                              => "l10",
        "PASS_WARN_AGE"                             => "l11",
        "PERMISSION_SECURITY"                       => "r5",
        "ROOT_LOGIN_REMOTE"                         => "r6",
        "RUN_UPDATEDB_AS"                           => "r7",
        "UID_MAX"                                   => "l12",
        "UID_MIN"                                   => "l13",
        "SYS_UID_MAX"                               => "l14",
        "SYS_UID_MIN"                               => "l15",
        "SYS_GID_MAX"                               => "l16",
        "SYS_GID_MIN"                               => "l17",
        "USERADD_CMD"                               => "l18",
        "USERDEL_PRECMD"                            => "l19",
        "USERDEL_POSTCMD"                           => "l20",
        "DISABLE_RESTART_ON_UPDATE"                 => "r13",
        "DISABLE_STOP_ON_REMOVAL"                   => "r14",
        "DISPLAYMANAGER_ROOT_LOGIN_REMOTE"          => "r16",
        "DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN" => "r17",
        "net.ipv4.tcp_syncookies"                   => "9",
        "net.ipv4.ip_forward"                       => "10",
        "net.ipv6.conf.all.forwarding"              => "11",
        "SYSTOHC"                                   => "r12",
        "SYSLOG_ON_NO_ERROR"                        => "r15",
        "SMTPD_LISTEN_REMOTE"                       => "r18",
        "DHCPD_RUN_CHROOTED"                        => "r19",
        "DHCPD_RUN_AS"                              => "r20",
        "HIBERNATE_SYSTEM"                          => "r21"
      }

      @E = { "target" => { "bash_output" => {} } }
      @R = {
        "sysconfig" => { "displaymanager" => { "DISPLAYMANAGER" => "" } },
        "target"    => {
          # FileUtils::Exists returns true:
          "stat" => { 1 => 2 }
        }
      }

      Security.Settings = deep_copy(@m)
      Security.modified = true
      TEST(lambda { Security.Write }, [@R, {}, @E], nil)

      nil
    end
  end
end

Yast::WriteClient.new.main
