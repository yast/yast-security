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

# File:	include/security/dialogs.ycp
# Package:	Security configuration
# Summary:	Dialogs definitions
# Authors:	Michal Svec <msvec@suse.cz>
#
# $Id$
module Yast
  module SecurityDialogsInclude
    def initialize_security_dialogs(include_target)
      Yast.import "UI"

      textdomain "security"

      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "Message"
      Yast.import "Security"
      Yast.import "Wizard"

      Yast.include include_target, "security/helps.rb"
      Yast.include include_target, "security/routines.rb"

      @display_manager = Security.display_manager

      @tree_dialogs = [
        "main",
        "overview",
        "password",
        "boot",
        "login",
        "users",
        "misc",
        :wizardTree
      ]

      @configurable_options = [
        "PERMISSION_SECURITY",
        "MANDATORY_SERVICES",
        "EXTRA_SERVICES",
        "kernel.sysrq"
      ]

      @UNKNOWN_STATUS = _("Unknown")

      @label_mapping = {
        "kernel.sysrq"                              => _("Use magic SysRq keys"),
        "PERMISSION_SECURITY"                       => _(
          "Use secure file permissions"
        ),
        "DISPLAYMANAGER_REMOTE_ACCESS"              => _(
          "Remote access to the display manager"
        ),
        "SYSLOG_ON_NO_ERROR"                        => _(
          "Always generate syslog message for cron scripts"
        ),
        "DHCPD_RUN_CHROOTED"                        => _(
          "Run the DHCP daemon in a chroot"
        ),
        "DHCPD_RUN_AS"                              => _(
          "Run the DHCP daemon as dhcp user"
        ),
        "DISPLAYMANAGER_ROOT_LOGIN_REMOTE"          => _(
          "Remote root login in the display manager"
        ),
        "DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN" => _(
          "Remote access to the X server"
        ),
        "SMTPD_LISTEN_REMOTE"                       => _(
          "Remote access to the email delivery subsystem"
        ),
        "DISABLE_RESTART_ON_UPDATE"                 => _(
          "Restart services on update"
        ),
        "DISABLE_STOP_ON_REMOVAL"                   => _(
          "Stop services on removal"
        ),
        "net.ipv4.tcp_syncookies"                   => _(
          "Enable TCP syncookies"
        ),
        "net.ipv4.ip_forward"                       => _("IPv4 forwarding"),
        "net.ipv6.conf.all.forwarding"              => _("IPv6 forwarding"),
        "MANDATORY_SERVICES"                        => _(
          "Enable basic system services"
        ),
        "EXTRA_SERVICES"                            => _(
          "Disable extra services"
        )
      }

      # mapping for "Enable" and "Disable" links
      # current value -> new value
      @link_value_mapping = {
        "yes" => "no",
        "no"  => "yes",
        "1"   => "0",
        "0"   => "1",
        true  => false,
        false => true
      }

      # mapping for "Configure" links
      # config name -> dialog name
      @link_config_mapping = {
        "PERMISSION_SECURITY" => "misc",
        "kernel.sysrq"        => "misc"
      }

      # mapping for "Configure" links
      # config name -> yast client
      @link_client_mapping = {
        "MANDATORY_SERVICES" => "services-manager",
        "EXTRA_SERVICES"     => "services-manager"
      }

      @link_update_mapping = {
        "MANDATORY_SERVICES" => lambda { Security.ReadServiceSettings },
        "EXTRA_SERVICES"     => lambda { Security.ReadServiceSettings }
      }
    end

    def SecurityStatus(option, plaintext)
      ret = ""

      value = Ops.get(Security.Settings, option, "")

      Builtins.y2milestone("Option: %1, value: %2", option, value)

      # handle the special cases at first
      if Builtins.contains(@configurable_options, option)
        ret = _("Configure")
      elsif ["1", "yes", true].include?(value)
        ret = _("Enabled")
      elsif ["0", "no", false].include?(value)
        ret = _("Disabled")
      else
        return @UNKNOWN_STATUS
      end

      return ret if plaintext

      Builtins.sformat("<A HREF=\"%1\">%2</A>", option, ret)
    end

    def OverviewText(type)
      ret = ""
      ret_table = []

      if type == :richtext
        # open a table
        ret = Builtins.sformat(
          "<TABLE><TR> <TD><BIG><B>%1</B></BIG></TD>\n" +
            "<TD ALIGN=center><BIG><B>&nbsp;&nbsp;&nbsp;&nbsp;%2&nbsp;&nbsp;&nbsp;&nbsp;</B></BIG></TD>\n" +
            "<TD ALIGN=center><BIG><B>&nbsp;&nbsp;&nbsp;&nbsp;%3&nbsp;&nbsp;&nbsp;&nbsp;</B></BIG></TD>\n" +
            "<TD></TD>\n" +
            "</TR> <TR></TR>",
          # table header
          _("Security Setting"),
          _("Status"),
          _("Security Status")
        )
      end

      security_mapping = [
        {
          "id"        => "kernel.sysrq",
          "is_secure" => Ops.get(Security.Settings, "kernel.sysrq", "0") == "0"
        },
        {
          "id"        => "PERMISSION_SECURITY",
          "is_secure" => Ops.get(Security.Settings, "PERMISSION_SECURITY", "") == "secure" ||
            Ops.get(Security.Settings, "PERMISSION_SECURITY", "") == "paranoid"
        },
        {
          "id"        => "DISPLAYMANAGER_REMOTE_ACCESS",
          "is_secure" => Ops.get(
            Security.Settings,
            "DISPLAYMANAGER_REMOTE_ACCESS",
            ""
          ) == "no"
        },
        {
          "id"        => "SYSLOG_ON_NO_ERROR",
          "is_secure" => Ops.get(Security.Settings, "SYSLOG_ON_NO_ERROR", "") == "yes"
        },
        {
          "id"        => "DHCPD_RUN_CHROOTED",
          "is_secure" => Ops.get(Security.Settings, "DHCPD_RUN_CHROOTED", "") == "yes"
        },
        {
          "id"        => "DHCPD_RUN_AS",
          "is_secure" => Ops.get(Security.Settings, "DHCPD_RUN_AS", "") == "dhcp"
        },
        {
          "id"        => "DISPLAYMANAGER_ROOT_LOGIN_REMOTE",
          "is_secure" => Ops.get(
            Security.Settings,
            "DISPLAYMANAGER_ROOT_LOGIN_REMOTE",
            ""
          ) == "no"
        },
        {
          "id"        => "DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN",
          "is_secure" => Ops.get(
            Security.Settings,
            "DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN",
            ""
          ) == "no"
        },
        {
          "id"        => "SMTPD_LISTEN_REMOTE",
          "is_secure" => Ops.get(Security.Settings, "SMTPD_LISTEN_REMOTE", "") == "no"
        },
        {
          "id"        => "DISABLE_RESTART_ON_UPDATE",
          "is_secure" => Ops.get(
            Security.Settings,
            "DISABLE_RESTART_ON_UPDATE",
            ""
          ) == "no"
        },
        {
          "id"        => "DISABLE_STOP_ON_REMOVAL",
          "is_secure" => Ops.get(
            Security.Settings,
            "DISABLE_STOP_ON_REMOVAL",
            ""
          ) == "no"
        },
        {
          "id"        => "net.ipv4.tcp_syncookies",
          "is_secure" => Security.Settings["net.ipv4.tcp_syncookies"]
        },
        {
          "id"        => "net.ipv4.ip_forward",
          "is_secure" => !Security.Settings["net.ipv4.ip_forward"]
        },
        {
          "id"        => "net.ipv6.conf.all.forwarding",
          "is_secure" => !Security.Settings["net.ipv6.conf.all.forwarding"]
        },
        {
          "id"        => "MANDATORY_SERVICES",
          "is_secure" => Security.Settings["MANDATORY_SERVICES"] == "secure"
        },
        {
          "id"        => "EXTRA_SERVICES",
          "is_secure" => Security.Settings["EXTRA_SERVICES"] == "secure"
        }
      ]

      Builtins.foreach(security_mapping) do |setting|
        id = Ops.get_string(setting, "id", "")
        case type
        when :table
          ret_table = Builtins.add(
            ret_table,
            Item(
              Id(id),
              Ops.get(@label_mapping, id, ""),
              SecurityStatus(id, true),
              Ops.get_boolean(setting, "is_secure", false) ? "\u2714" : "\u2718"
            )
          )
        when :richtext
          # add one line for each security setting
          ret = Ops.add(
            ret,
            Builtins.sformat(
              "<TR><TD>%1&nbsp;&nbsp;&nbsp;&nbsp;</TD><TD ALIGN=center>%2</TD><TD ALIGN=center>&nbsp;&nbsp;&nbsp;%3</TD><TD>%4</TD></TR>",
              Ops.get(@label_mapping, id, ""),
              SecurityStatus(id, false),
              Ops.get_boolean(setting, "is_secure", false) ?
                "<SUP><FONT COLOR=green SIZE=20>\u2714</FONT></SUP>" :
                "<FONT COLOR=red SIZE=20><SUP>\u2718</SUP></FONT>",
              Builtins.haskey(@help_mapping, id) ?
                Builtins.sformat(
                  "<A HREF=\"help_%1\">%2</A>&nbsp;&nbsp;<BR>",
                  id,
                  _("Help")
                ) :
                ""
            )
          )
        end
      end

      case type
      when :table
        Builtins.y2debug("Overview table: %1", ret_table)
        return deep_copy(ret_table)
      when :richtext
        # close the table
        ret = Ops.add(ret, "</TABLE>")

        Builtins.y2debug("Overview text: %1", ret)
        return ret
      end

      Builtins.y2error("Unknown type: %1", type)

      nil
    end

    def DisplayHelpPopup(help_id)
      help = Ops.get(@help_mapping, help_id, "")

      # add the warning if the option is unknown
      if SecurityStatus(help_id, true) == @UNKNOWN_STATUS
        help = Ops.add(help, Ops.get_string(@HELPS, "unknown_status", ""))
      end

      # add extra help to service related options
      case help_id
      when "MANDATORY_SERVICES"
        missing = Security.MissingMandatoryServices

        if missing != nil && missing != []
          srvs = ""

          Builtins.foreach(missing) do |l|
            # this is a separator between service names
            # e.g.: "postfix" + " or " + "sendmail"
            group = Builtins.mergestring(l, _(" or "))
            srvs = Ops.add(Ops.add(srvs, group), "<BR>")
          end

          # richtext message: %1 = runlevel ("3" or "5"), %2 = list of services
          help +=
            _("<P>These basic system services are not enabled:<BR><B>%s</B></P>") % srvs
        else
          help += _("<P>All basic services are enabled.</P>")
        end
      when "EXTRA_SERVICES"
        extra = Security.ExtraServices

        if extra != nil && extra != []
          srvs = Builtins.mergestring(extra, "<BR>")
          help +=
            _("<P>These extra services are enabled:<BR><B>%s</B></P>") % srvs
          help += _("<P>Check the list of services and disable all unused services.</P>")
        else
          help += _("<P>Only basic system services are enabled.</P>")
        end
      end

      if help != nil && help != ""
        Popup.LongText(
          Ops.get(@label_mapping, help_id, _("Description")),
          RichText(help),
          70,
          15
        )
      end

      nil
    end

    def OverviewDialog
      # Overview dialog caption
      caption = _("Security Overview")
      help = Ops.get_string(@HELPS, "overview", "")
      no_richtext = !Ops.get_boolean(
        UI.GetDisplayInfo,
        "RichTextSupportsTable",
        true
      )

      # table header
      tabheader = Header(
        _("Security Setting"),
        _("Status"),
        Center(_("Security Status"))
      )
      contents = no_richtext ?
        Table(Id(:table), Opt(:immediate), tabheader, OverviewText(:table)) :
        RichText(Id(:rtext), OverviewText(:richtext))

      if no_richtext
        # add a button box below the table
        contents = VBox(
          contents,
          VSpacing(1),
          HBox(
            # push button label
            PushButton(Id(:change), _("Change &Status")),
            HSpacing(2),
            # push button label
            PushButton(Id(:descr), _("&Description"))
          ),
          VSpacing(1)
        )
      end

      Wizard.SetContentsButtons(
        caption,
        contents,
        help,
        Label.BackButton,
        Label.OKButton
      )

      Wizard.HideBackButton
      Wizard.SetAbortButton(:abort, Label.CancelButton)

      # select the dialog in the tree navigation
      Wizard.SelectTreeItem("overview")

      ret = nil
      while true
        ret = UI.UserInput

        # abort?
        if ret == :abort || ret == :cancel
          if ReallyAbort()
            break
          else
            next
          end
        elsif ret == :back || ret == :next ||
            Builtins.contains(@tree_dialogs, ret)
          # the current item has been selected, do not change to the same dialog
          if ret == "overview"
            # preselect the item if it has been unselected
            Wizard.SelectTreeItem("overview") if Wizard.QueryTreeItem != "overview"

            next
          end

          break
        # user clicked a link in the richtext
        elsif (Ops.is_string?(ret) && Builtins.haskey(Security.Settings, ret)) ||
            ret == :change
          if ret == :change
            # query the table in textmode
            ret = Convert.to_string(UI.QueryWidget(Id(:table), :CurrentItem))
          end

          Builtins.y2milestone("Clicked %1 link", ret)

          current_value = Ops.get(Security.Settings, Convert.to_string(ret), "")
          new_value = @link_value_mapping[current_value]

          # set the new value and refresh the overview
          if Builtins.haskey(@link_value_mapping, current_value) &&
              new_value != current_value
            Builtins.y2milestone("New value for %1: %2", ret, new_value)
            Ops.set(Security.Settings, Convert.to_string(ret), new_value)
            # the config has been changed
            Security.SetModified

            if no_richtext
              UI.ChangeWidget(Id(:table), :Items, OverviewText(:table))
              UI.ChangeWidget(Id(:table), :CurrentItem, ret)
              UI.SetFocus(Id(:table))
            else
              UI.ChangeWidget(Id(:rtext), :Value, OverviewText(:richtext))
            end
          elsif Builtins.haskey(@link_config_mapping, ret)
            new_dialog = Ops.get_string(@link_config_mapping, ret, "")

            Builtins.y2milestone("Switching to dialog %1", new_dialog)
            return new_dialog
          elsif Builtins.haskey(@link_client_mapping, ret)
            client = Ops.get_string(@link_client_mapping, ret, "")

            if client != ""
              Builtins.y2milestone("Calling Yast client %1", client)
              client_ret = WFM.CallFunction(client, [])
              Builtins.y2milestone("Client returned %1", client_ret)

              if client_ret == :next || client_ret == :ok ||
                  client_ret == :finish || client_ret == true
                # update the current value
                if @link_update_mapping.has_key?(ret)
                  Popup.Feedback(_("Analyzing system"), Message.takes_a_while) do
                    @link_update_mapping[ret].call
                  end
                end

                # update the overview
                if no_richtext
                  UI.ChangeWidget(Id(:table), :Items, OverviewText(:table))
                  UI.ChangeWidget(Id(:table), :CurrentItem, ret)
                  UI.SetFocus(Id(:table))
                else
                  UI.ChangeWidget(Id(:rtext), :Value, OverviewText(:richtext))
                end
              end
            end
          else
            Builtins.y2error("Unknown action for link %1", ret)
          end
        elsif (Ops.is_string?(ret) &&
            Builtins.regexpmatch(Convert.to_string(ret), "^help_")) ||
            ret == :descr
          help_id = no_richtext ?
            Convert.to_string(UI.QueryWidget(Id(:table), :CurrentItem)) :
            Builtins.regexpsub(Convert.to_string(ret), "^help_(.*)", "\\1")
          Builtins.y2milestone("Clicked help link: %1", help_id)

          DisplayHelpPopup(help_id)

          # switch the focus back to the table in text/GTK UI
          UI.SetFocus(Id(:table)) if no_richtext
        elsif ret == :table
          # disable "Change Status" button if the action is unknown
          current_item = Convert.to_string(
            UI.QueryWidget(Id(:table), :CurrentItem)
          )
          status = SecurityStatus(
            current_item, # plaintext
            true
          )

          UI.ChangeWidget(Id(:change), :Enabled, status != @UNKNOWN_STATUS)
        else
          Builtins.y2error("Unexpected return code: %1", ret)
          next
        end
      end

      deep_copy(ret)
    end

    def vbox_boot_permissions
      display_manager_widget = Empty()
      if @display_manager && !@display_manager.shutdown_var_name.empty?
        display_manager_widget = VBox(
          VSpacing(1.0),
          settings2widget(@display_manager.shutdown_var_name)
        )
      end

      VBox(
        VSpacing(1),
        settings2widget("CONSOLE_SHUTDOWN"),
        display_manager_widget,
        VSpacing(1.0),
        settings2widget("HIBERNATE_SYSTEM"),
        VSpacing(1)
      )
    end

    # Boot dialog
    # @return dialog result
    def BootDialog
      # Boot dialog caption
      caption = _("Boot Settings")
      help = Ops.get_string(@HELPS, "boot", "")

      # Boot dialog contents
      contents = HVCenter(
        HVSquash(
          HBox(
            HSpacing(5),
            VBox(
              VSpacing(2),
              # Frame label
              Frame(
                _("Boot Permissions"),
                HBox(
                  HSpacing(3),
                  vbox_boot_permissions,
                  HSpacing(3)
                )
              ),
              VSpacing(2)
            ),
            HSpacing(5)
          )
        )
      )

      Wizard.SetContentsButtons(
        caption,
        contents,
        help,
        Label.BackButton,
        Label.OKButton
      )

      Wizard.HideBackButton
      Wizard.SetAbortButton(:abort, Label.CancelButton)

      # select the dialog in the tree navigation
      Wizard.SelectTreeItem("boot")

      ret = nil
      while true
        ret = UI.UserInput

        # abort?
        if ret == :abort || ret == :cancel
          if ReallyAbort()
            break
          else
            next
          end
        elsif ret == :back || ret == :next ||
            Builtins.contains(@tree_dialogs, ret)
          # the current item has been selected, do not change to the same dialog
          if ret == "boot"
            # preselect the item if it has been unselected
            Wizard.SelectTreeItem("boot") if Wizard.QueryTreeItem != "boot"

            next
          end

          break
        else
          Builtins.y2error("Unexpected return code: %1", ret)
          next
        end
      end

      if ret == :next || Builtins.contains(@tree_dialogs, ret)
        widget2settings("CONSOLE_SHUTDOWN")
        if @display_manager && !@display_manager.shutdown_var_name.empty?
          widget2settings(@display_manager.shutdown_var_name)
        end
        widget2settings("HIBERNATE_SYSTEM")
      end

      deep_copy(ret)
    end

    # Misc dialog
    # @return dialog result
    def MiscDialog
      # Misc dialog caption
      caption = _("Miscellaneous Settings")
      help = Ops.get_string(@HELPS, "misc", "")

      # Misc dialog contents
      contents = VBox(
        VSeparator(),
        settings2widget("PERMISSION_SECURITY"),
        VSpacing(1.0),
        settings2widget("RUN_UPDATEDB_AS"),
        VSpacing(1.0),
        settings2widget("kernel.sysrq"),
        VSpacing(1.8)
      )
      contents = HVCenter(
        HVSquash(
          HBox(
            HSpacing(5),
            VBox(VSpacing(2), ReplacePoint(Id(:rp_main), contents), VSpacing(2)),
            HSpacing(5)
          )
        )
      )

      Wizard.SetContentsButtons(
        caption,
        contents,
        help,
        Label.BackButton,
        Label.OKButton
      )

      Wizard.HideBackButton
      Wizard.SetAbortButton(:abort, Label.CancelButton)

      # select the dialog in the tree navigation
      Wizard.SelectTreeItem("misc")

      ret = nil
      while true
        ret = UI.UserInput

        # abort?
        if ret == :abort || ret == :cancel
          if ReallyAbort()
            break
          else
            next
          end
        elsif ret == :back
          break
        elsif ret == :next || Builtins.contains(@tree_dialogs, ret)
          # the current item has been selected, do not change to the same dialog
          if ret == "misc"
            # preselect the item if it has been unselected
            Wizard.SelectTreeItem("misc") if Wizard.QueryTreeItem != "misc"

            next
          end

          # check_*
          break
        else
          Builtins.y2error("Unexpected return code: %1", ret)
          next
        end
      end

      if ret == :next || Builtins.contains(@tree_dialogs, ret)
        widget2settings("PERMISSION_SECURITY")
        widget2settings("RUN_UPDATEDB_AS")
        widget2settings("kernel.sysrq")
      end

      deep_copy(ret)
    end

    # Password dialog
    # @return dialog result
    def PassDialog
      # Password dialog caption
      caption = _("Password Settings")
      help = Ops.get_string(@HELPS, "password", "")

      # Password dialog contents
      contents = VBox(
        # Frame label
        XFrame(
          0.3,
          0.15,
          _("Checks"),
          VBox(
            settings2widget("PASSWD_USE_PWQUALITY"),
            VSeparator(),
            settings2widget("PASS_MIN_LEN"),
            VSeparator(),
            settings2widget("PASSWD_REMEMBER_HISTORY"),
            VSeparator()
          )
        ),
        VSpacing(0.4),
        settings2widget("PASSWD_ENCRYPTION"),
        VSpacing(0.4),
        # Frame label
        Frame(
          _("Password Age"),
          HBox(
            HSpacing(0.4),
            settings2widget("PASS_MIN_DAYS"),
            HSpacing(0.4),
            settings2widget("PASS_MAX_DAYS"),
            HSpacing(0.4)
          )
        ),
        VSpacing(0.15),
        settings2widget("PASS_WARN_AGE"),
        VSpacing(0.0)
      )
      contents = HVCenter(
        HVSquash(
          HBox(
            HSpacing(5),
            VBox(VSpacing(2), ReplacePoint(Id(:rp_main), contents), VSpacing(2)),
            HSpacing(5)
          )
        )
      )

      Wizard.SetContentsButtons(
        caption,
        contents,
        help,
        Label.BackButton,
        Label.OKButton
      )

      Wizard.HideBackButton
      Wizard.SetAbortButton(:abort, Label.CancelButton)

      # select the dialog in the tree navigation
      Wizard.SelectTreeItem("password")

      UI.ChangeWidget(
        Id("PASS_MIN_LEN"),
        :Enabled,
        Ops.get(Security.Settings, "PASSWD_USE_PWQUALITY", "") == "yes"
      )

      ret = nil
      while true
        ret = UI.UserInput

        # abort?
        if ret == :abort || ret == :cancel
          if ReallyAbort()
            break
          else
            next
          end
        elsif ret == :back
          break
        elsif ret == "PASSWD_USE_PWQUALITY"
          # minlen is an option for pam_pwquality
          UI.ChangeWidget(
            Id("PASS_MIN_LEN"),
            :Enabled,
            UI.QueryWidget(Id(ret), :Value) == true
          )
        elsif ret == :next || Builtins.contains(@tree_dialogs, ret)
          # the current item has been selected, do not change to the same dialog
          if ret == "password"
            # preselect the item if it has been unselected
            Wizard.SelectTreeItem("password") if Wizard.QueryTreeItem != "password"

            next
          end

          # check_*
          if checkMinMax("PASS_MIN_DAYS", "PASS_MAX_DAYS") != true
            # Popup text
            Popup.Error(
              _(
                "The minimum number of days cannot be larger\nthan the maximum."
              )
            )
            next
          end
          enc = Convert.to_string(
            UI.QueryWidget(Id("PASSWD_ENCRYPTION"), :Value)
          )
          min = Convert.to_integer(UI.QueryWidget(Id("PASS_MIN_LEN"), :Value))
          if Ops.greater_than(
            min,
            Ops.get_integer(Security.PasswordMaxLengths, enc, 8)
          )
            # Popup text, %1 is number
            Popup.Error(
              Builtins.sformat(
                _(
                  "The minimum password length cannot be larger than the maximum.\nThe maximum password length for the selected encryption method is %1."
                ),
                Ops.get_integer(Security.PasswordMaxLengths, enc, 8)
              )
            )
            next
          end
          break
        elsif ret != "PASSWD_ENCRYPTION"
          Builtins.y2error("Unexpected return code: %1", ret)
          next
        end
      end

      if ret == :next || Builtins.contains(@tree_dialogs, ret)
        widget2settings("PASS_MIN_DAYS")
        widget2settings("PASS_MAX_DAYS")
        widget2settings("PASS_MIN_LEN")
        widget2settings("PASSWD_USE_PWQUALITY")
        widget2settings("PASS_WARN_AGE")
        widget2settings("PASSWD_ENCRYPTION")
        widget2settings("PASSWD_REMEMBER_HISTORY")
      end

      deep_copy(ret)
    end

    # Login dialog
    # @return dialog result
    def LoginDialog
      # Login dialog caption
      caption = _("Login Settings")
      help = Ops.get_string(@HELPS, "login", "")

      # Login dialog contents
      contents = VBox(
        # Frame label
        XFrame(
          3.0,
          1.0,
          _("Login"),
          VBox(
            # VSeparator(),
            settings2widget("FAIL_DELAY"), # VSeparator()
            # VSeparator(),
            VSpacing(0.5),
            VSeparator(),
            settings2widget("DISPLAYMANAGER_REMOTE_ACCESS")
          )
        ) # ,`VSpacing(1.7)
      )
      contents = HVCenter(
        HVSquash(
          HBox(
            HSpacing(5),
            VBox(VSpacing(2), ReplacePoint(Id(:rp_main), contents), VSpacing(2)),
            HSpacing(5)
          )
        )
      )

      Wizard.SetContentsButtons(
        caption,
        contents,
        help,
        Label.BackButton,
        Label.OKButton
      )

      Wizard.HideBackButton
      Wizard.SetAbortButton(:abort, Label.CancelButton)

      # select the dialog in the tree navigation
      Wizard.SelectTreeItem("login")

      ret = nil
      while true
        ret = UI.UserInput

        # abort?
        if ret == :abort || ret == :cancel
          if ReallyAbort()
            break
          else
            next
          end
        elsif ret == :back
          break
        elsif ret == :next || Builtins.contains(@tree_dialogs, ret)
          # the current item has been selected, do not change to the same dialog
          if ret == "login"
            # preselect the item if it has been unselected
            Wizard.SelectTreeItem("login") if Wizard.QueryTreeItem != "login"

            next
          end

          # check_*
          break
        else
          Builtins.y2error("Unexpected return code: %1", ret)
          next
        end
      end

      if ret == :next || Builtins.contains(@tree_dialogs, ret)
        widget2settings("FAIL_DELAY")
        widget2settings("DISPLAYMANAGER_REMOTE_ACCESS")
      end

      deep_copy(ret)
    end
  end
end
