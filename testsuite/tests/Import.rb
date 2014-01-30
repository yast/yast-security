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
  class ImportClient < Client
    def main
      Yast.include self, "testsuite.rb"

      Yast.import "Security"

      @import_map = {
        "CONSOLE_SHUTDOWN"                          => "reboot",
        "DISPLAYMANAGER_REMOTE_ACCESS"              => "r4",
        "ENCRYPTION"                                => "md5",
        "ENABLE_SYSRQ"                              => "yes",
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
        "SYSTEM_UID_MAX"                            => "l14", # old syntax
        "SYSTEM_UID_MIN"                            => "l15",
        "SYS_GID_MAX"                               => "l16",
        "SYS_GID_MIN"                               => "l17",
        "USERADD_CMD"                               => "l18",
        "USERDEL_PRECMD"                            => "l19",
        "USERDEL_POSTCMD"                           => "l20",
        "DISABLE_RESTART_ON_UPDATE"                 => "r13",
        "DISABLE_STOP_ON_REMOVAL"                   => "r14",
        "DISPLAYMANAGER_ROOT_LOGIN_REMOTE"          => "r16",
        "DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN" => "r17",
        "IP_TCP_SYNCOOKIES"                         => "yes",
        "IP_FORWARD"                                => "0",
        "IPV6_FORWARD"                              => "yes"
      }

      @E = { "target" => { "bash_output" => {} } }
      @R = { "sysconfig" => { "displaymanager" => { "DISPLAYMANAGER" => "" } } }

      TEST(lambda { Security.Import(@import_map) }, [@R, {}, @E], nil)

      DUMP(Security.Settings)

      DUMP(Ops.get(Security.Settings, "SYS_UID_MIN", ""))
      DUMP(Ops.get(Security.Settings, "SYS_UID_MAX", ""))
      DUMP(Ops.get(Security.Settings, "SYS_GID_MIN", ""))
      DUMP(Ops.get(Security.Settings, "SYS_GID_MAX", ""))

      nil
    end
  end
end

Yast::ImportClient.new.main
