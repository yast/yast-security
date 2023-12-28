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

# File:	include/security/wizards.ycp
# Package:	Security configuration
# Summary:	Wizards definitions
# Authors:	Michal Svec <msvec@suse.cz>
#
# $Id$
module Yast
  module SecurityUsersInclude
    def initialize_security_users(include_target)
      textdomain "security"

      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "Wizard"

      Yast.include include_target, "security/helps.rb"
      Yast.include include_target, "security/routines.rb"
    end

    # Adduser dialog
    # @return dialog result
    def AdduserDialog
      # Adduser dialog caption
      caption = _("User Addition")
      help = Ops.get_string(@HELPS, "adduser", "")

      # Adduser dialog contents
      contents = VBox(
        VSeparator(),
        # Frame label
        XFrame(
          1.8,
          0.5,
          _("User ID Limitations"),
          HBox(
            settings2widget("UID_MIN"),
            HSpacing(1.5),
            settings2widget("UID_MAX")
          )
        ),
        VSpacing(0.7),
        # Frame label
        XFrame(
          1.8,
          0.5,
          _("Group ID Limitations"),
          HBox(
            settings2widget("GID_MIN"),
            HSpacing(1.5),
            settings2widget("GID_MAX")
          )
        ),
        VSpacing(1.7)
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
      Wizard.SelectTreeItem("users")

      ret = nil
      loop do
        ret = UI.UserInput

        # abort?
        if [:abort, :cancel].include?(ret)
          ReallyAbort() ? break : next
        # back
        elsif ret == :back
          break
        # next
        elsif ret == :next || Builtins.contains(@tree_dialogs, ret)
          # the current item has been selected, do not change to the same dialog
          if ret == "users"
            # preselect the item if it has been unselected
            Wizard.SelectTreeItem("users") if Wizard.QueryTreeItem != "users"

            next
          end

          if checkMinMax("UID_MIN", "UID_MAX") != true
            # Popup text
            Popup.Error(
              _("The minimum user ID cannot be larger than the maximum.")
            )
            next
          end
          if checkMinMax("GID_MIN", "GID_MAX") != true
            # Popup text
            Popup.Error(
              _("The minimum group ID cannot be larger than the\nmaximum.")
            )
            next
          end
          break
        else
          Builtins.y2error("Unexpected return code: %1", ret)
          next
        end
      end

      if ret == :next || Builtins.contains(@tree_dialogs, ret)
        widget2settings("GID_MIN")
        widget2settings("GID_MAX")
        widget2settings("UID_MIN")
        widget2settings("UID_MAX")
      end

      deep_copy(ret)
    end
  end
end
