# encoding: utf-8

# ------------------------------------------------------------------------------
# Copyright (c) 2006-2012 Novell, Inc. All Rights Reserved.
#
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of version 2 of the GNU General Public License as published by the
# Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, contact Novell, Inc.
#
# To contact Novell about this file by physical or electronic mail, you may find
# current contact information at www.novell.com.
# ------------------------------------------------------------------------------

# File:	modules/Security.ycp
# Package:	Security configuration
# Summary:	Data for the security configuration
# Authors:	Michal Svec <msvec@suse.cz>
#
# $Id$
require "yast"

module Yast
  class SecurityClass < Module

    include Yast::Logger

    def main
      Yast.import "UI"
      textdomain "security"

      Yast.import "FileUtils"
      Yast.import "Package"
      Yast.import "Pam"
      Yast.import "Progress"
      Yast.import "SystemdService"

      Yast.include self, "security/levels.rb"


      # services to check - these must be running
      # meaning [ [ || ] && && ]
      @mandatory_services = [
        ["ntp"],
        ["syslog"],
        ["auditd"],
        ["random"],
        ["kbd"],
        ["cron"],
        ["postfix", "sendmail"]
      ]
      # sevices to check - these can be ignored (if they are running it's OK)
      @optional_services = [
        "acpid",
        "boot.clock",
        "dbus",
        "ealysyslog",
        "fbset",
        "framebufferset",
        "isdn",
        "microcode.ctl",
        "random",
        "consolekit",
        "haldaemon",
        "network",
        "syslog",
        "auditd",
        "splash_early",
        "alsasound",
        "irq_balancer",
        "kbd",
        "powersaved",
        "splash",
        "sshd",
        "earlyxdm",
        "hotkey-setup",
        "atd",
        "nscd",
        "smpppd",
        "xend",
        "autofs",
        "libvirtd",
        "sendmail",
        "postfix",
        "xendomains",
        "cron",
        "ddclient",
        "smartd",
        "stopblktrace",
        "ntp",
        "SuSEfirewall",
        "earlysyslog"
      ]
      # All other services should be turned off

      # systemd target, defining ctrl-alt-del behavior
      @ctrl_alt_del_file = "/etc/systemd/system/ctrl-alt-del.target"

      # encryption methods supported by pam_unix (bnc#802006)
      @encryption_methods = ["des", "md5", "sha256", "sha512"]

      # All security settings
      @Settings = {
        "CONSOLE_SHUTDOWN"                          => "reboot",
        "CRACKLIB_DICT_PATH"                        => "/usr/lib/cracklib_dict",
        "DISPLAYMANAGER_REMOTE_ACCESS"              => "no",
        "kernel.sysrq"                              => "0",
        "net.ipv4.tcp_syncookies"                   => "1",
        "net.ipv4.ip_forward"                       => "0",
        "net.ipv6.conf.all.forwarding"              => "0",
        "FAIL_DELAY"                                => "3",
        "GID_MAX"                                   => "60000",
        "GID_MIN"                                   => "1000",
        "DISPLAYMANAGER_SHUTDOWN"                   => "all",
        "HIBERNATE_SYSTEM"                          => "active_console",
        "PASSWD_ENCRYPTION"                         => "sha512",
        "PASSWD_USE_CRACKLIB"                       => "yes",
        "PASS_MAX_DAYS"                             => "99999",
        "PASS_MIN_DAYS"                             => "0",
        "PASS_MIN_LEN"                              => "5",
        "PASS_WARN_AGE"                             => "7",
        "PERMISSION_SECURITY"                       => "secure",
        "DISABLE_RESTART_ON_UPDATE"                 => "no",
        "DISABLE_STOP_ON_REMOVAL"                   => "no",
        "RUN_UPDATEDB_AS"                           => "nobody",
        "UID_MAX"                                   => "60000",
        "UID_MIN"                                   => "500",
        "SYS_UID_MAX"                               => "499",
        "SYS_UID_MIN"                               => "100",
        "SYS_GID_MAX"                               => "499",
        "SYS_GID_MIN"                               => "100",
        "USERADD_CMD"                               => "/usr/sbin/useradd.local",
        "USERDEL_PRECMD"                            => "/usr/sbin/userdel-pre.local",
        "USERDEL_POSTCMD"                           => "/usr/sbin/userdel-post.local",
        "PASSWD_REMEMBER_HISTORY"                   => "0",
        "SYSTOHC"                                   => "yes",
        "SYSLOG_ON_NO_ERROR"                        => "yes",
        "DISPLAYMANAGER_ROOT_LOGIN_REMOTE"          => "no",
        "DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN" => "no",
        "SMTPD_LISTEN_REMOTE"                       => "no",
        "RUNLEVEL3_MANDATORY_SERVICES"              => "yes",
        "RUNLEVEL5_MANDATORY_SERVICES"              => "yes",
        "RUNLEVEL3_EXTRA_SERVICES"                  => "no",
        "RUNLEVEL5_EXTRA_SERVICES"                  => "no"
      }

      # the original settings
      @Settings_bak = deep_copy(@Settings)

      # keys that should not be tested against predefined levels:
      # - RUNLEVEL*_SERVICES have different syntax, are not saved in current form
      @do_not_test = [
        "RUNLEVEL3_MANDATORY_SERVICES",
        "RUNLEVEL5_MANDATORY_SERVICES",
        "RUNLEVEL3_EXTRA_SERVICES",
        "RUNLEVEL5_EXTRA_SERVICES"
      ]

      # Security settings locations
      @Locations = {
        ".etc.login_defs"           => [
          "FAIL_DELAY",
          "GID_MAX",
          "GID_MIN",
          "PASS_MAX_DAYS",
          "PASS_MIN_DAYS",
          "PASS_WARN_AGE",
          "UID_MAX",
          "UID_MIN",
          "SYS_UID_MAX",
          "SYS_UID_MIN",
          "SYS_GID_MAX",
          "SYS_GID_MIN",
          "USERADD_CMD",
          "USERDEL_PRECMD",
          "USERDEL_POSTCMD"
        ],
        ".sysconfig.displaymanager" => [
          "DISPLAYMANAGER_REMOTE_ACCESS",
          "DISPLAYMANAGER_ROOT_LOGIN_REMOTE",
          "DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN",
          "DISPLAYMANAGER_SHUTDOWN"
        ],
        ".sysconfig.security"       => ["PERMISSION_SECURITY"],
        ".sysconfig.services"       => [
          "DISABLE_RESTART_ON_UPDATE",
          "DISABLE_STOP_ON_REMOVAL"
        ],
        ".sysconfig.locate"         => ["RUN_UPDATEDB_AS"],
        ".sysconfig.clock"          => ["SYSTOHC"],
        ".sysconfig.cron"           => ["SYSLOG_ON_NO_ERROR"],
        ".sysconfig.mail"           => ["SMTPD_LISTEN_REMOTE"]
      }

      # Default values for /etc/sysctl.conf keys
      @sysctl = {
        "kernel.sysrq"                 => "0",
        "net.ipv4.tcp_syncookies"      => "1",
        "net.ipv4.ip_forward"          => "0",
        "net.ipv6.conf.all.forwarding" => "0"
      }

      # Mapping of /etc/sysctl.conf keys to old (obsoleted) sysconfig ones
      # (used during autoYaST import
      @sysctl2sysconfig = {
        "kernel.sysrq"                 => "ENABLE_SYSRQ",
        "net.ipv4.tcp_syncookies"      => "IP_TCP_SYNCOOKIES",
        "net.ipv4.ip_forward"          => "IP_FORWARD",
        "net.ipv6.conf.all.forwarding" => "IPV6_FORWARD"
      }

      # Mapping of /etc/login.defs keys to old (obsoleted) ones
      # (used during autoYaST import)
      @obsolete_login_defs = {
        "SYS_UID_MAX" => "SYSTEM_UID_MAX",
        "SYS_UID_MIN" => "SYSTEM_UID_MIN",
        "SYS_GID_MAX" => "SYSTEM_GID_MAX",
        "SYS_GID_MIN" => "SYSTEM_GID_MIN"
      }

      # mapping of internal YaST values to values needed for
      # org.freedesktop.upower.hibernate privilege
      @ycp2polkit = {
        "active_console" => "auth_admin:auth_admin:yes",
        "auth_admin"     => "auth_admin:auth_admin:auth_admin",
        "anyone"         => "yes:yes:yes"
      }

      # Remaining settings:
      # - CONSOLE_SHUTDOWN (/etc/inittab)
      # - PASSWD_ENCRYPTION (/etc/pam?)
      # - RUNLEVEL3_MANDATORY_SERVICES
      # - RUNLEVEL5_MANDATORY_SERVICES
      # - RUNLEVEL3_EXTRA_SERVICES
      # - RUNLEVEL5_EXTRA_SERVICES

      # Number of sigificant characters in the password
      @PasswordMaxLengths = {
        "des"    => 8,
        "md5"    => 127,
        "sha256" => 127,
        "sha512" => 127
      }

      # Abort function
      # return boolean return true if abort
      @AbortFunction = nil

      # Data was modified?
      @modified = false

      @proposal_valid = false
      @write_only = false


      @activation_mapping = {
        "SYSLOG_ON_NO_ERROR"           => "/etc/init.d/boot.clock start",
        "DHCPD_RUN_CHROOTED"           => "/etc/init.d/dhcpd restart",
        "DHCPD_RUN_AS"                 => "/etc/init.d/dhcpd restart",
        # restart sendmail or postfix - whatever is installed
        "SMTPD_LISTEN_REMOTE"          => "(test -e /etc/init.d/sendmail && VERBOSE=false /usr/lib/sendmail.d/update && /etc/init.d/sendmail restart) || (test -e /etc/init.d/postfix && /usr/sbin/SuSEconfig.postfix && /etc/init.d/postfix restart)",
        "net.ipv4.tcp_syncookies"      => "/etc/init.d/boot.ipconfig start",
        "net.ipv4.ip_forward"          => "/etc/init.d/boot.ipconfig start",
        "net.ipv6.conf.all.forwarding" => "/etc/init.d/boot.ipconfig start"
      }
    end

    # List of missing mandatory services
    #
    # @param [Array<String>] enabled_services optional list with names of the
    #     currently enabled services. If not provided, it will be obtained
    #     from SystemdService.
    def MissingMandatoryServices(enabled_services = nil)
      log.info("Checking mandatory services")

      enabled_services ||= SystemdService.all.select(&:enabled?).map(&:name)
      log.info("enabled_services: #{enabled_services}")
      return nil if enabled_services.nil?

      ret = @mandatory_services.select do |services|
        enabled = services.any? { |service| enabled_services.include?(service) }
        log.info("Mandatory services #{services} are enabled: #{enabled}")
        !enabled
      end 

      log.info("Missing mandatory services: #{ret}")
      deep_copy(ret)
    end

    # List of enabled services that are neither mandatory nor optional
    #
    # @param [Array<String>] enabled_services optional list with names of the
    #     currently enabled services. If not provided, it will be obtained
    #     from SystemdService.
    def ExtraServices(enabled_services = nil)
      log.info("Searching for extra services")

      enabled_services ||= SystemdService.all.select(&:enabled?).map(&:name)
      return nil if enabled_services == nil

      mandatory = @mandatory_services.flatten
      ret = enabled_services.select do |service|
        # the extra service is not mandatory and it's not optional
        extra = !mandatory.include?(service) && !@optional_services.include?(service)
        log.info("Found extra service: #{service}") if extra
        extra
      end 
      log.info("All extra services: #{ret}")

      deep_copy(ret)
    end

    # Check for pending Abort press
    # @return true if pending abort
    def PollAbort
      UI.PollInput == :abort
    end

    # Abort function
    # @return blah blah lahjk
    def Abort
      return Builtins.eval(@AbortFunction) == true if @AbortFunction != nil
      false
    end

    # Function which returns if the settings were modified
    # @return [Boolean]  settings were modified
    def GetModified
      @modified
    end

    # Function sets internal variable, which indicates, that any
    # settings were modified, to "true"
    def SetModified
      @modified = true

      nil
    end

    # Data was modified?
    # @return true if modified
    def Modified
      Builtins.y2debug("modified=%1", @modified)
      @modified
    end

    def ReadServiceSettings
      services = SystemdService.all.select(&:enabled?).map(&:name)
      setting = MissingMandatoryServices(services) == [] ? "secure" : "insecure"
      # Runlevels are not longer used, but @Settings is populated this way for
      # compatibility with the current interface
      @Settings["RUNLEVEL3_MANDATORY_SERVICES"] = @Settings["RUNLEVEL5_MANDATORY_SERVICES"] = setting
      setting = ExtraServices(services) == [] ? "secure" : "insecure"
      @Settings["RUNLEVEL3_EXTRA_SERVICES"] = @Settings["RUNLEVEL5_EXTRA_SERVICES"] = setting

      nil
    end

    # Read the information about ctrl+alt+del behavior
    # See bug 742783 for description
    def ReadConsoleShutdown
      ret = "ignore"

      if Package.Installed("systemd")
        if !FileUtils.Exists(@ctrl_alt_del_file)
          ret = "reboot"
        else
          link = Convert.to_string(
            SCR.Read(path(".target.symlink"), @ctrl_alt_del_file)
          )
          if link == "/lib/systemd/system/poweroff.target"
            ret = "halt"
          elsif link == "/lib/systemd/system/reboot.target" ||
              link == "/lib/systemd/system/ctrl-alt-del.target"
            ret = "reboot"
          end
        end
        return ret
      end
      inittab = SCR.Dir(path(".etc.inittab"))
      if Builtins.contains(inittab, "ca")
        ca = Convert.to_string(SCR.Read(path(".etc.inittab.ca")))
        if Builtins.issubstring(ca, "/bin/true") ||
            Builtins.issubstring(ca, "/bin/false")
          Ops.set(@Settings, "CONSOLE_SHUTDOWN", "ignore")
        elsif Builtins.issubstring(ca, "reboot") ||
            Builtins.issubstring(ca, " -r")
          Ops.set(@Settings, "CONSOLE_SHUTDOWN", "reboot")
        elsif Builtins.issubstring(ca, "halt") ||
            Builtins.issubstring(ca, " -h")
          Ops.set(@Settings, "CONSOLE_SHUTDOWN", "halt")
        else
          Builtins.y2error("Unknown ca status: %1", ca)
          Ops.set(@Settings, "CONSOLE_SHUTDOWN", "ignore")
        end
      else
        Ops.set(@Settings, "CONSOLE_SHUTDOWN", "ignore")
      end

      nil
    end

    # Read the settings from the files included in @Locations
    def read_from_locations
      # NOTE: the call to #sort is only needed to satisfy the old testsuite
      @Locations.sort.each do |file, vars|
        vars.each do |var|
          val = ""
          filename = nil
          if file.include?("sysconfig")
            filename = "/etc" + file.gsub(".", "/")
            log.info "filename=#{filename}"
          end
          if filename.nil? || SCR.Read(path(".target.size"), filename) > 0
            val = SCR.Read(path("#{file}.#{var}"))
            log.debug "Reading: #{file}.#{var} (#{val})"
          end
          @Settings[var] = val unless val.nil?
        end
      end
    end

    # Read the settings from sysctl.conf
    def read_kernel_settings
      # NOTE: the call to #sort is only needed to satisfy the old testsuite
      @sysctl.sort.each do |key, default_value|
        val = SCR.Read(path(".etc.sysctl_conf") + key)
        val = default_value if val.nil? || val == ""
        @Settings[key] = val
      end
    end

    # Read all security settings
    # @return true on success
    def Read
      @Settings = {}
      @modified = false

      # Read security settings
      read_from_locations
      Builtins.y2milestone("Settings=%1", @Settings)

      Ops.set(@Settings, "CONSOLE_SHUTDOWN", ReadConsoleShutdown())

      Builtins.y2debug("Settings=%1", @Settings)


      # Read runlevel setting
      ReadServiceSettings()

      # Read pam settings

      method = Convert.to_string(
        SCR.Read(path(".etc.login_defs.ENCRYPT_METHOD"))
      )
      if method == nil ||
          !Builtins.contains(@encryption_methods, Builtins.tolower(method))
        method = "des"
      end
      Ops.set(@Settings, "PASSWD_ENCRYPTION", Builtins.tolower(method))

      # cracklib and pwhistory settings
      Ops.set(@Settings, "PASS_MIN_LEN", "5")
      Ops.set(@Settings, "PASSWD_USE_CRACKLIB", "no")
      Ops.set(@Settings, "PASSWD_REMEMBER_HISTORY", "0")

      pam_cracklib = Pam.Query("cracklib")
      if Ops.greater_than(Builtins.size(pam_cracklib), 0)
        Ops.set(@Settings, "PASSWD_USE_CRACKLIB", "yes")
      end
      # save the default value
      Ops.set(@Settings, "CRACKLIB_DICT_PATH", "/usr/lib/cracklib_dict")
      Builtins.foreach(Ops.get_list(pam_cracklib, "password", [])) do |val|
        lval = Builtins.splitstring(val, "=")
        if Builtins.issubstring(val, "dictpath=")
          Ops.set(
            @Settings,
            "CRACKLIB_DICT_PATH",
            Ops.get_string(lval, 1, "/usr/lib/cracklib_dict")
          )
        end
        if Builtins.issubstring(val, "minlen=") &&
            Ops.get_string(lval, 1, "") != ""
          Ops.set(@Settings, "PASS_MIN_LEN", Ops.get_string(lval, 1, "5"))
        end
      end

      pam_history = Pam.Query("pwhistory")
      Builtins.foreach(Ops.get_list(pam_history, "password", [])) do |val|
        lval = Builtins.splitstring(val, "=")
        if Builtins.issubstring(val, "remember=") &&
            Ops.get_string(lval, 1, "") != ""
          Ops.set(
            @Settings,
            "PASSWD_REMEMBER_HISTORY",
            Ops.get_string(lval, 1, "0")
          )
        end
      end

      Builtins.y2debug("Settings=%1", @Settings)

      # Local permissions hack

      perm = Ops.get(@Settings, "PERMISSION_SECURITY", "")
      if Builtins.issubstring(perm, "easy")
        perm = "easy"
      elsif Builtins.issubstring(perm, "paranoid")
        perm = "paranoid"
      elsif Builtins.issubstring(perm, "secure")
        perm = "secure"
      else
        perm = "secure"
      end
      Ops.set(@Settings, "PERMISSION_SECURITY", perm)
      Builtins.y2debug("Settings=%1", @Settings)

      # read local polkit settings
      action = "org.freedesktop.upower.hibernate"
      hibernate = Convert.to_string(
        SCR.Read(Builtins.add(path(".etc.polkit-default-privs_local"), action))
      )
      if hibernate != nil
        Ops.set(@Settings, "HIBERNATE_SYSTEM", "active_console")
        if hibernate == "auth_admin:auth_admin:auth_admin"
          Ops.set(@Settings, "HIBERNATE_SYSTEM", "auth_admin")
        end
        if hibernate == "yes:yes:yes"
          Ops.set(@Settings, "HIBERNATE_SYSTEM", "anyone")
        end
      end
      Builtins.y2debug(
        "HIBERNATE_SYSTEM: %1",
        Ops.get(@Settings, "HIBERNATE_SYSTEM", "")
      )

      read_kernel_settings
      Builtins.y2debug("Settings=%1", @Settings)

      # remember the read values
      @Settings_bak = deep_copy(@Settings)
      true
    end

    # Write the value of ctrl-alt-delete behavior
    def write_console_shutdown(ca)
      if Package.Installed("systemd")
        if ca == "reboot"
          SCR.Execute(path(".target.remove"), @ctrl_alt_del_file)
        elsif ca == "halt"
          SCR.Execute(
            path(".target.bash"),
            Builtins.sformat(
              "ln -s -f /lib/systemd/system/poweroff.target %1",
              @ctrl_alt_del_file
            )
          )
        else
          SCR.Execute(
            path(".target.bash"),
            Builtins.sformat("ln -s -f /dev/null %1", @ctrl_alt_del_file)
          )
        end
        return true
      end

      if ca == "reboot"
        SCR.Write(
          path(".etc.inittab.ca"),
          ":ctrlaltdel:/sbin/shutdown -r -t 4 now"
        )
      elsif ca == "halt"
        SCR.Write(
          path(".etc.inittab.ca"),
          ":ctrlaltdel:/sbin/shutdown -h -t 4 now"
        )
      else
        SCR.Write(path(".etc.inittab.ca"), ":ctrlaltdel:/bin/true")
      end
      SCR.Write(path(".etc.inittab"), nil)

      # re-read the modified inittab (#83480)
      SCR.Execute(path(".target.bash"), "/sbin/telinit q")
      true
    end

    # Write the settings from @Locations to the corresponding files
    def write_to_locations
      commitlist = []
      # NOTE: the call to #sort is only needed to satisfy the old testsuite
      @Locations.sort.each do |file, vars|
        vars.each do |var|
          val = @Settings[var]
          if val && val != SCR.Read(path("#{file}.#{var}"))
            SCR.Write(path("#{file}.#{var}"), val)
            commitlist << file unless commitlist.include?(file)
          end
        end
      end
      commitlist.each do |file|
        SCR.Write(path(file), nil)
      end
    end

    # Write settings related to PAM behavior
    def write_pam_settings
      # pam stuff
      encr = @Settings.fetch("PASSWD_ENCRYPTION", "sha512")
      if encr != @Settings_bak["PASSWD_ENCRYPTION"]
        SCR.Write(path(".etc.login_defs.ENCRYPT_METHOD"), encr)
      end

      # use cracklib?
      if @Settings["PASSWD_USE_CRACKLIB"] == "yes"
        Pam.Add("cracklib")
        pth = @Settings["CRACKLIB_DICT_PATH"]
        if pth && pth != "/usr/lib/cracklib_dict"
          Pam.Add("--cracklib-dictpath=#{pth}")
        end
      else
        Pam.Remove("cracklib")
      end

      # save min pass length
      min_len = @Settings["PASS_MIN_LEN"]
      if min_len && min_len != "5" && @Settings["PASSWD_USE_CRACKLIB"] == "yes"
        Pam.Add("cracklib") # minlen is part of cracklib
        Pam.Add("cracklib-minlen=#{min_len}")
      else
        Pam.Remove("cracklib-minlen")
      end

      # save "remember" value (number of old user passwords to not allow)
      remember_history = @Settings["PASSWD_REMEMBER_HISTORY"]
      if remember_history && remember_history != "0"
        Pam.Add("pwhistory")
        Pam.Add("pwhistory-remember=#{remember_history}")
      else
        Pam.Remove("pwhistory-remember")
      end
    end

    # Write settings related to sysctl.conf and sysrq
    def write_kernel_settings
      # write sysctl.conf
      written = false
      # NOTE: the call to #sort is only needed to satisfy the old testsuite
      @sysctl.sort.each do |key, default_value|
        val = @Settings.fetch(key, default_value)
        int_val = Integer(val) rescue nil
        if int_val.nil?
          log.error "value #{val} for #{key} is not integer, not writing"
        elsif val != SCR.Read(path(".etc.sysctl_conf") + key)
          SCR.Write(path(".etc.sysctl_conf") + key, val)
          written = true
        end
      end
      SCR.Write(path(".etc.sysctl_conf"), nil) if written

      # enable sysrq?
      sysrq = Integer(@Settings.fetch("kernel.sysrq", "0")) rescue nil
      if sysrq != nil
        SCR.Execute(
          path(".target.bash"),
          "echo #{sysrq} > /proc/sys/kernel/sysrq"
        )
      end
    end

    # Write local PolicyKit configuration
    def write_polkit_settings
      if @Settings.fetch("HIBERNATE_SYSTEM", "") !=
          @Settings_bak.fetch("HIBERNATE_SYSTEM", "")
        # allow writing any value (different from predefined ones)
        ycp_value = @Settings.fetch("HIBERNATE_SYSTEM", "active_console")
        hibernate = @ycp2polkit.fetch(ycp_value, ycp_value)
        action = "org.freedesktop.upower.hibernate"
        SCR.Write(
          path(".etc.polkit-default-privs_local") + action,
          hibernate
        )
      end
    end

    # Ensures that file permissions and PolicyKit privileges are applied
    def apply_new_settings
      # apply all current permissions as they are now
      # (what SuSEconfig --module permissions would have done)
      SCR.Execute(path(".target.bash"), "/usr/bin/chkstat --system")

      # ensure polkit privileges are applied (bnc #541393)
      if FileUtils.Exists("/sbin/set_polkit_default_privs")
        SCR.Execute(path(".target.bash"), "/sbin/set_polkit_default_privs")
      end
    end

    # Executes the corresponding activation command for the settings that have
    # an entry in @activation_mapping and have changed
    def activate_changes
      # NOTE: the call to #sort is only needed to satisfy the old testsuite
      @activation_mapping.sort.each do |setting, action|
        if @Settings[setting] != @Settings_bak[setting]
          log.info(
            "Option #{setting} has been modified, "\
            "activating the change: #{action}"
          )
          res = SCR.Execute(path(".target.bash"), action)
          log.error "Activation failed" if res != 0
        end
      end
    end

    # Write all security settings
    # @return true on success
    def Write
      return true if !@modified
      log.info "Writing configuration"

      # Security read dialog caption
      caption = _("Saving Security Configuration")
      steps = 4

      Progress.New(
        caption,
        " ",
        steps,
        [
          # Progress stage 1/4
          _("Write security settings"),
          # Progress stage 2/4
          _("Write inittab settings"),
          # Progress stage 3/4
          _("Write PAM settings"),
          # Progress stage 4/4
          _("Update system settings")
        ],
        [
          # Progress step 1/5
          _("Writing security settings..."),
          # Progress step 2/5
          _("Writing inittab settings..."),
          # Progress step 3/5
          _("Writing PAM settings..."),
          # Progress step 4/5
          _("Updating system settings..."),
          # Progress step 5/5
          _("Finished")
        ],
        ""
      )

      log.debug "Settings=#{@Settings}"

      # Write security settings
      return false if Abort()
      Progress.NextStage
      @Settings["PERMISSION_SECURITY"] << " local"
      write_to_locations

      # Write inittab settings
      return false if Abort()
      Progress.NextStage
      write_console_shutdown(@Settings.fetch("CONSOLE_SHUTDOWN", "ignore"))

      # Write authentication and privileges settings
      return false if Abort()
      Progress.NextStage
      write_pam_settings
      write_polkit_settings
      write_kernel_settings

      # Finish him
      return false if Abort()
      Progress.NextStage
      apply_new_settings

      return false if Abort()
      Progress.NextStage
      activate_changes

      return false if Abort()
      @modified = false
      true
    end

    # Get all security settings from the first parameter
    # (For use by autoinstallation.)
    # @param [Hash] settings The YCP structure to be imported.
    # @return [Boolean] True on success
    def Import(settings)
      settings = deep_copy(settings)
      return true if settings == {}

      @modified = true
      tmpSettings = {}
      Builtins.foreach(@Settings) do |k, v|
        if !Builtins.haskey(settings, k)
          if Builtins.haskey(@sysctl, k) &&
              Builtins.haskey(settings, Ops.get(@sysctl2sysconfig, k, ""))
            val = Ops.get_string(
              settings,
              Ops.get(@sysctl2sysconfig, k, ""),
              ""
            )
            if val == "yes"
              Ops.set(tmpSettings, k, "1")
            elsif val == "no"
              Ops.set(tmpSettings, k, "0")
            else
              Ops.set(tmpSettings, k, val)
            end
          elsif Builtins.haskey(settings, Ops.get(@obsolete_login_defs, k, ""))
            Ops.set(
              tmpSettings,
              k,
              Ops.get_string(settings, Ops.get(@obsolete_login_defs, k, ""), "")
            )
          else
            Ops.set(tmpSettings, k, v)
          end
        else
          Ops.set(tmpSettings, k, Ops.get_string(settings, k, ""))
        end
      end
      @Settings = Convert.convert(
        Builtins.eval(tmpSettings),
        :from => "map",
        :to   => "map <string, string>"
      )
      true
    end

    # Dump the security settings to a single map
    # (For use by autoinstallation.)
    # @return [Hash] Dumped settings (later acceptable by Import ())
    def Export
      Builtins.eval(@Settings)
    end

    # Create a textual summary and a list of unconfigured cards
    # @return summary of the current configuration
    def Summary
      settings = deep_copy(@Settings)
      Builtins.foreach(@do_not_test) do |key|
        settings = Builtins.remove(settings, key)
      end

      # Determine current settings
      current = :custom
      Builtins.maplist(@Levels) do |key, level|
        Builtins.y2debug("%1=%2", key, level)
        current = key if level == settings
      end
      Builtins.y2debug("%1=%2", current, @Settings)

      # Summary text
      summary = _("Current Security Level: Custom settings")
      if current != :custom
        # Summary text
        summary = Builtins.sformat(
          _("Current Security Level: %1"),
          Ops.get(@LevelsNames, Convert.to_string(current), "")
        )
      end

      [summary, []]
    end

    # Create an overview table with all configured cards
    # @return table items
    def Overview
      []
    end

    publish :variable => :mandatory_services, :type => "const list <list <string>>"
    publish :variable => :optional_services, :type => "const list <string>"
    publish :function => :MissingMandatoryServices, :type => "list <list <string>> ()"
    publish :function => :ExtraServices, :type => "list <string> ()"
    publish :variable => :Settings, :type => "map <string, string>"
    publish :variable => :do_not_test, :type => "list <string>"
    publish :variable => :PasswordMaxLengths, :type => "map"
    publish :variable => :AbortFunction, :type => "block <boolean>"
    publish :function => :PollAbort, :type => "boolean ()"
    publish :function => :Abort, :type => "boolean ()"
    publish :variable => :modified, :type => "boolean"
    publish :variable => :proposal_valid, :type => "boolean"
    publish :variable => :write_only, :type => "boolean"
    publish :function => :GetModified, :type => "boolean ()"
    publish :function => :SetModified, :type => "void ()"
    publish :function => :Modified, :type => "boolean ()"
    publish :function => :ReadServiceSettings, :type => "void ()"
    publish :function => :ReadConsoleShutdown, :type => "string ()"
    publish :function => :Read, :type => "boolean ()"
    publish :function => :Write, :type => "boolean ()"
    publish :function => :Import, :type => "boolean (map)"
    publish :function => :Export, :type => "map ()"
    publish :function => :Summary, :type => "list ()"
    publish :function => :Overview, :type => "list ()"
  end

  Security = SecurityClass.new
  Security.main
end
