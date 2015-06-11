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

# File:	include/security/helps.ycp
# Module:	Security configuration
# Summary:	Helps definition
# Authors:	Michal Svec <msvec@suse.cz>
#
# $Id$
#
# This file contains all helps for the security module screens.
# They are in one huge map called HELPS.
module Yast
  module SecurityHelpsInclude
    def initialize_security_helps(include_target)
      textdomain "security"

      # All helps are here
      @HELPS = {
        # Read dialog help 1/2
        "read"           => _(
          "<p><b><big>Initializing Security Configuration</big></b>\n<br>Please wait...<br></p>"
        ) +
          # Read dialog help 2/2
          _(
            "<p><b><big>Aborting the Initialization</big></b><br>\nSafely abort the configuration utility by pressing <b>Abort</b> now.</p>"
          ),
        # Write dialog help 1/2
        "write"          => _(
          "<p><b><big>Saving Security Configuration</big></b>\n<br>Please wait...<br></p>"
        ) +
          # Write dialog help 2/2
          _(
            "<p><b><big>Aborting Saving</big></b><br>\nAbort the save procedure by pressing <b>Abort</b>.</p>"
          ),
        # Boot dialog help 1/4
        "boot"           => _(
          "<p><b><big>Boot Security</big></b></p>\n<p>In this dialog, change various boot settings related to security.</p>"
        ) +
          # Boot dialog help 2/4
          _(
            "<p><b>Interpretation of Ctrl + Alt + Del</b>:\n" +
              "Configure what the system should do in response to\n" +
              "someone at the console pressing the CTRL + ALT + DEL key\n" +
              "combination. Usually the system reboots. Sometimes it is desirable\n" +
              "to ignore this event, for example, when the system serves as both\n" +
              "workstation and server.</p>"
          ) +
          # Boot dialog help 3/4
          _(
            "<p><b>Shutdown Behaviour of Login Manager</b>:\nSet who is allowed to shut down the machine from KDM.</p>\n"
          ) +
          # Boot dialog help 4/4
          _(
            "<p><b>Hibernate System</b>:\n" +
              "Set the conditions for allowing users to hibernate the system. By default, user on active console has such right.\n" +
              "Other options are allowing the action to any user or requiring authentication in all cases.</p>\n"
          ),
        # Main dialog help 1/8
        "main"           => _(
          "<P><BIG><B>Configuring Local Security</B></BIG></P>\n" +
            "<p>Using predefined defaults, change the local security settings, which include\n" +
            "    booting, login, password, user creation, and file permissions. The default\n" +
            "    settings can be modified as needed.\n" +
            "</p>"
        ) +
          # Main dialog help 5/8
          _(
            "<p><b>Home Workstation</b>: For a home computer not connected to\nany type of a network.</p>"
          ) +
          # Main dialog help 6/8
          _(
            "<p><b>Networked Workstation</b>: For a computer connected\nto any type of network including the Internet.</p>"
          ) +
          # Main dialog help 7/8
          _(
            "<p><b>Network Server</b>: For a computer that provides\nany type of service.</p>"
          ) +
          # Main dialog help 8/8
          _("<p><b>Custom Settings</b>: Create your own configuration.</p>"),
        # Login dialog help 1/4
        "login"          => _(
          "<p><big><b>Login Security</b></big></p>\n" +
            "<p>These login settings\n" +
            "are mainly stored in the /etc/login.defs file.</p>"
        ) +
          # Login dialog help 2/4
          _(
            "<p><b>Delay after Incorrect Login Attempt:</b>\n" +
              "It is advisable to wait some time after an incorrect login attempt to prevent\n" +
              "password guessing. Make the time small enough that users do not need to wait to\n" +
              "retry if a password is mistyped. A sensible value is three seconds (<tt>3</tt>).</p>"
          ) +
          # Login dialog help 3/4
          _(
            "<p><b>Record Successful Login Attempts:</b> Logging successful login\n" +
              "attempts is useful. It can warn you of unauthorized access to the\n" +
              "system (for example, a user logging in from a different location than usual).\n" +
              "</p>\n"
          ) +
          # Login dialog help 4/4
          _(
            "<p><b>Allow Remote Graphical Login:</b> Checking this allows access\n" +
              "to a graphical login screen for this machine over the network. Remote access\n" +
              "to your machine using a display manager might be a security risk.</p>"
          ),
        # Password dialog help 1/8
        "password"       => _(
          "<p>These password settings\nare mainly stored in the /etc/login.defs file.</p>"
        ) +
          # Password dialog help 2/8
          _(
            "<p><b>Check New Passwords</b>: It is wise to choose a password that\n" +
              "cannot be found in a dictionary and is not a name or other simple, common word.\n" +
              "By checking the box, enforce password checking in regard to these rules.</p>"
          ) +
          # Password dialog help
          _(
            "<p><b>Minimum Acceptable Password Length:</b>\n" +
              "The minimum acceptable size for the new password reduced by the number\n" +
              "of different character classes (other, upper, lower and digit) used in the new\n" +
              "password. See man pam_cracklib for a more detailed explanation.\n" +
              "This option can only be modified when <b>Check New Passwords</b> is set.</p>"
          ) +
          # Password dialog help 4/8
          _(
            "<p><b>Passwords to Remember</b>:\n" +
              "Enter the number of user passwords to store and prevent the user from reusing.\n" +
              "Enter 0 if passwords should not be stored.</p>"
          ) +
          # Password dialog help 5a/8
          _("<p><b>Password Encryption Method:</b></p>") +
          # Password dialog help 5b/8
          _(
            "<p><b>DES</b>, the Linux default method, works in all network environments,\n" +
              "but it restricts you to passwords no longer than eight characters. If you need\n" +
              "compatibility with other systems, use this method.</p>"
          ) +
          # Password dialog help 5c/8
          _(
            "<p><b>MD5</b> allows longer passwords and is supported by all current Linux \ndistributions, but not by other systems or old software.</p>"
          ) +
          # Password dialog help 5d/8
          _(
            "<p><b>SHA-512</b> is the current standard hash method, using other algorithms is not recommended unless needed for compatibility purpose.</p>"
          ) +
          # Password dialog help 7/8
          _(
            "<p><b>Password Age:</b> Set the minimum and\nmaximum number of days a password may be used.</p>"
          ) +
          # Password dialog help 8/8
          _(
            "<p><b>Days before Password Expires Warning</b>: This entry sets the\n" +
              "number of days users are warned before their passwords expire. The longer the\n" +
              "time, the less likely it is that someone can guess passwords.</p>"
          ),
        # Adduser dialog help 1/2
        "adduser"        => _(
          "<p><big><b>User Security</b></big></P>\n<p>In this dialog, change various settings used to create users.</p>"
        ) +
          # Adduser dialog help 2/3
          _(
            "<p><b>User ID Limitations:</b>\nSet the minimum and maximum possible user ID.</p>"
          ) +
          # Adduser dialog help 3/3
          _(
            "<p><b>Group ID Limitations</b>:\nSet the minimum and maximum possible group ID.</p>"
          ),
        # Misc dialog help 1/14
        "misc"           => _(
          "<p><big><b>Other Security Settings</b></big></P>\n<p>In this dialog, change miscellaneous settings related to local security.</p>"
        ) +
          # Misc dialog help 2/14
          _(
            "<p><b>File Permissions</b>: Settings for the permissions\n" +
              "of certain system files are set according to the data in /etc/permissions.secure\n" +
              "or /etc/permissions.easy. Which file is used depends on this selection.\n" +
              "Launching SuSEconfig sets these permissions according to /etc/permissions.*.\n" +
              "This fixes files with incorrect permissions, whether this occurred accidentally\n" +
              "or by intruders.</p><p>\n" +
              "With <b>Easy</b>, most of the system files that are only readable by root\n" +
              "in Secure are modified so other users can also read these files.\n" +
              "Using <b>Secure</b>, certain system files, such as /var/log/messages, can only\n" +
              "be viewed by the user root. Some programs can only be launched by root or by\n" +
              "daemons, not by ordinary users.\n" +
              "The most secure setting is <b>Paranoid</B>. With it, you must\n" +
              "decide which users are able to run X applications and setuid programs.</p>\n"
          ) +
          # Misc dialog help 6/14
          _(
            "<p><b>User Launching updatedb</b>: The program updatedb runs \n" +
              "once a day. It scans your entire file system and creates a database (locatedb)\n" +
              "that stores the location of every file. The database can be searched by the\n" +
              "program \"locate\".  Here, set the user that runs this command: <b>nobody</b>\n" +
              "    (few files) or <b>root</b> (all files).</p>"
          ) +
          # Misc dialog help 10/14
          _(
            "<p><b>Current Directory in root's Path</b> On a DOS system,\n" +
              "the system first searches for executable files (programs) in the current\n" +
              "directory then in the current path variable. In contrast, a UNIX-like system\n" +
              "searches for them exclusively via the search path (variable PATH).</p>"
          ) +
          # Misc dialog help 11/14
          _(
            "<p><b>Current Directory in the Path of Regular Users</b><br> A DOS\n" +
              "system first searches for executable files (programs) in the current directory\n" +
              "then in the current path variable. In contrast, a UNIX-like system searches\n" +
              "for them exclusively via the search path (variable PATH).</p>"
          ) +
          # Misc dialog help 12/14
          _(
            "<p>Some systems set up a work-around by adding the dot (\".\") to the\n" +
              "search path, enabling files in the current path to be found and executed.\n" +
              "This is highly dangerous because you may accidentally launch unknown programs in\n" +
              "the current directory instead of the usual systemwide files. As a result,\n" +
              "executing <i>Trojan Horses</i>, which exploit this weakness and invade your system,\n" +
              "is rather easy if you set this option.</p>"
          ) +
          # Misc dialog help 13/14
          _(
            "<p>\"yes\": the dot (\".\") is attached to the end of the search\npath of root, making it the last to be searched.</p>"
          ) +
          # Misc dialog help 14/14
          _(
            "<p>\"no\": the user root always must launch programs in the\ncurrent directory prefixed with a \"./\". Example: \"./configure\".</p>"
          ) +
          # Misc dialog help 14/14
          _(
            "<p><b>Enable Magic SysRq Keys</b><br> If you check this option, you\n" +
              "will have some control over the system even if it crashes (for example, during kernel\n" +
              "debugging). For details, see /usr/src/linux/Documentation/sysrq.txt</p>"
          ),
        # help text: security overview dialog 1/
        "overview"       => _(
          "<P><B>Security Overview</B><BR>This overview shows the most important security settings.</P>"
        ) +
          # help text: security overview dialog 1/
          _(
            "<P>To change the current value, click the link associated to the option.</P>"
          ) +
          # help text: security overview dialog 1/
          _(
            "<P> A check mark in the <B>Security Status</B> column means that the current value of the option is secure.</P>"
          ),
        # an error message (rich text)
        "unknown_status" => _(
          "<P><B>The current value could not be read. The service is probably not installed or the option is missing on the system.</B></P>"
        )
      }

      @help_mapping = {
        "DISPLAYMANAGER_REMOTE_ACCESS"              => _(
          "<P>A display manager provides a graphical login screen and can be accessed\n" +
            "across the network by an X server running on another system if so\n" +
            "configured.</P><P>The windows that are being displayed would then transmit\n" +
            "their data across the network. If that network is not fully trusted, then the\n" +
            "network traffic can be eavesdropped by an attacker, gaining access not only to\n" +
            "the graphical content of the display, but also to usernames and passwords that\n" +
            "are being used.</P><P>If you do not need <EM>XDMCP</EM> for remote graphical\n" +
            "logins, then disable this option.</P>"
        ),
        "SYSTOHC"                                   => _(
          "<P>Upon startup, the system time is being set from the hardware clock of the\n" +
            "computer. As a consequence, setting the hardware clock before shutting down is\n" +
            "necessary.</P><P>Consistent system time is essential for the system to create\n" +
            "correct log messages.</P>"
        ),
        "SYSLOG_ON_NO_ERROR"                        => _(
          "<P>Malfunctions in a system are usually detected by anomalies in its behaviour. Syslog messages about events that reoccur on a regular basis are important to find causes of problems. And the absence of a single record can tell more than the absence of all log records.</P><P>Therefore, syslog messages of system events are only useful if they are present.</P>"
        ),
        "DHCPD_RUN_CHROOTED"                        => _(
          "<P>Chroot execution environments restrict a process to only access files that it needs by placing them in a separate subdirectory and running the process with a changed root (chroot) set to that directory.</P>"
        ),
        "DHCPD_RUN_AS"                              => _(
          "<P>The DHCP client daemon should run as the user <EM>dhcpd</EM> to minimize a possible threat if the service is found vulnerable to a weakness in its program code.</P><P>Note that dhcpd must never run as <EM>root</EM> or with the <EM>CAP_SYS_CHROOT</EM> capability for the chroot execution confinement to be effective.</P>"
        ),
        "DISPLAYMANAGER_ROOT_LOGIN_REMOTE"          => _(
          "<P>Administrators should never log on as <EM>root</EM> into an X Window session to minimize the usage of the root privileges.</P><P>This option does not help against careless administrators, but shall prevent attackers to be able to log on as <EM>root</EM> via the display manager if they guess or otherwise acquire the password.</P>"
        ),
        "DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN" => _(
          "<P>X Window clients, e.g. programs that open a window on your display, connect\n" +
            "to the X server that runs on the physical machine. Programs can also run on a\n" +
            "different system and display their content on the X server through network\n" +
            "connections.</P><P>When enabled, the X server listens on a port 6000 plus the\n" +
            "display number. Since network traffic is transferred unencrypted and therefore\n" +
            "subject to network sniffing, and since the port held open by the X server\n" +
            "offers attack options, the secure setting is to disable it.</P><P>To display X\n" +
            "Window clients across a network, we recommend the use of secure shell (<EM>ssh</EM>), which allows the X Window clients to connect to the X server through the encrypted ssh connection.</P>"
        ),
        "SMTPD_LISTEN_REMOTE"                       => _(
          "<P>The email delivery subsystem is always started. However, it does not expose\nitself outside the system by default, since it does not listen on the SMTP network port 25.</P><P>If you do not deliver emails to your system through the SMTP protocol, then disable this option.</P>"
        ),
        "DISABLE_RESTART_ON_UPDATE"                 => _(
          "<P>If a package containing a service that is currently running is being\n" +
            "updated, the service is restarted after the files in the package have been\n" +
            "installed.</P><P>This makes sense in most cases, and it is safe to do,\n" +
            "considering that many services either need their binaries or configuration\n" +
            "files accessible in the file system. Otherwise these services would continue\n" +
            "to run until the services are stopped, e.g. running daemons are\n" +
            "killed.</P><P>This setting should only be changed if there is a specific\n" +
            "reason to do so.</P>"
        ),
        "DISABLE_STOP_ON_REMOVAL"                   => _(
          "<P>If a package containing a service that is currently running is being\n" +
            "uninstalled, the service is stopped before the files of the package are\n" +
            "removed.</P><P>This makes sense in most cases, and it is safe to do,\n" +
            "considering that many services either need their binaries or configuration\n" +
            "files accessible in the file system. Otherwise these services would continue\n" +
            "to run until they are stopped, e.g. running daemons are\n" +
            "killed.</P><P>This setting should only be changed if there is a specific\n" +
            "reason to do so.</P>"
        ),
        "net.ipv4.tcp_syncookies"                   => _(
          "<P>A system can be overwhelmed with numerous connection attempts so that the system runs out of memory, leading to a Denial of Service (DoS) vulnerability.</P><P>The use of syncookies is a method that can help in such situations. But in configurations with a very large number of legitimate connection attempts from one source, the <EM>Enabled</EM> setting can cause problems with denied TCP connections under high load.</P><P>Still, for most environments, syncookies are the first line of defense against SYN flood DoS attacks, so the secure setting is <EM>Enabled</EM>.</P>"
        ),
        "net.ipv4.ip_forward"                       => _(
          "<P>IP forwarding means to pass on network packets that have been received, but that are not destined for one of the system's configured network interfaces, e.g. network interface addresses.</P><P>If a system forwards network traffic on ISO/OSI layer 3, it is called a router. If you do not need that routing functionality, then disable this option.</P>"
        ) +
          _("<P>This setting applies to <EM>IPv4</EM> only.</P>"),
        "net.ipv6.conf.all.forwarding"              => _(
          "<P>IP forwarding means to pass on network packets that have been received, but that are not destined for one of the system's configured network interfaces, e.g. network interface addresses.</P><P>If a system forwards network traffic on ISO/OSI layer 3, it is called a router. If you do not need that routing functionality, then disable this option.</P>"
        ) +
          _("<P>This setting applies to <EM>IPv6</EM> only.</P>"),
        "kernel.sysrq"                              => _(
          "<P>Magic SysRq Keys enable some control over the system even if it crashes (e.g. during kernel debugging) or if the system does not respond.</P>"
        ),
        "PERMISSION_SECURITY"                       => _(
          "<P>There are predefined file permissions in /etc/permissions.* files. The most restrictive file permissions are defined 'secure' or 'paranoid' file.</P>"
        ),
        "MANDATORY_SERVICES"                        => _(
          "<P>Basic system services must be enabled to provide system consistency and to run the security-related services.</P>"
        ),
        "EXTRA_SERVICES"                            => _(
          "<P>Every running service is a potential target of a security attack. Therefore it is recommended to turn off all services which are not used by the system.</P>"
        )
      } 


      # EOF
    end
  end
end
