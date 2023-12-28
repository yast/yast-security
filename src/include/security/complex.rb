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

# File:	include/security/complex.ycp
# Package:	Security configuration
# Summary:	Complex dialogs definitions
# Authors:	Michal Svec <msvec@suse.cz>
#
# $Id$
module Yast
  module SecurityComplexInclude
    def initialize_security_complex(include_target)
      Yast.import "UI"

      textdomain "security"

      Yast.import "Label"
      Yast.import "Security"
      Yast.import "Wizard"

      Yast.include include_target, "security/helps.rb"
      Yast.include include_target, "security/levels.rb"
      Yast.include include_target, "security/routines.rb"
      Yast.include include_target, "security/dialogs.rb"
    end

    # Write settings dialog
    # @return `next if success, else `abort
    def WriteDialog
      Wizard.RestoreHelp(Ops.get_string(@HELPS, "write", ""))
      Security.AbortFunction = lambda { Security.PollAbort }
      ret = Security.Write
      ret ? :next : :abort
    end

    # Main dialog
    # @return dialog result
    def MainDialog
      # Main dialog caption
      caption = _("Local Security Configuration")
      help = Ops.get_string(@HELPS, "main", "")

      settings = deep_copy(Security.Settings)
      Builtins.foreach(Security.do_not_test) do |key|
        settings = Builtins.remove(settings, key)
      end

      # Determine current settings
      current = :custom
      Builtins.maplist(@Levels) do |key, level|
        Builtins.y2debug("%1=%2", key, level)
        current = key if level == settings
      end
      Builtins.y2debug("%1=%2", current, Security.Settings)

      # Create RB group from the list of settings
      _RB = VBox()
      _RB = Builtins.add(_RB, VSpacing(0.5))
      Builtins.mapmap(@LevelsLabels) do |key, name|
        _RB = Builtins.add(
          _RB,
          Left(RadioButton(Id(key), Opt(:notify), name, key == current))
        )
        _RB = Builtins.add(_RB, VSpacing(0.03))
        { 0 => 0 }
      end
      _RB = Builtins.add(_RB, VSpacing(0.6))
      # RadioButton label
      _RB = Builtins.add(
        _RB,
        Left(
          RadioButton(
            Id(:custom),
            Opt(:notify),
            _("&Custom Settings"),
            current == :custom
          )
        )
      )
      _RB = Builtins.add(_RB, VSpacing(0.5))
      Builtins.y2debug("RB=%1", _RB)

      # Main dialog contents
      contents = HVCenter(
        VBox(
          HVSquash(
            # Frame caption
            Frame(
              _("Security Settings"),
              HBox(HSpacing(0.8), RadioButtonGroup(Id(:rb), _RB), HSpacing(0.8))
            )
          ),
          VSpacing(0.6)
        )
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

      ret = nil
      while true
        cur = UI.QueryWidget(Id(:rb), :CurrentButton)
        ret = UI.UserInput

        # abort?
        if ret == :abort || ret == :cancel
          if ReallyAbort()
            break
          else
            next
          end
        elsif ret == :back || ret == :next
          break
        elsif ret == :custom
          next
        elsif Ops.is_string?(ret) || ret == :wizardTree
          if Builtins.contains(@tree_dialogs, ret)
            # the current item has been selected, do not change to the same dialog
            if ret == "main"
              # preselect the item if it has been unselected
              Wizard.SelectTreeItem("main") if Wizard.QueryTreeItem != "main"

              next
            end

            # switch to another dialog
            break
          end
          if !Builtins.haskey(@Levels, Convert.to_string(ret))
            Builtins.y2error("Unexpected return code (key missing): %1", ret)
            next
          end
          next
        else
          Builtins.y2error("Unexpected return code: %1", ret)
          next
        end
      end

      if ret == :next || Builtins.contains(@tree_dialogs, ret)
        cur = UI.QueryWidget(Id(:rb), :CurrentButton)

        Builtins.y2debug("current=%1", current)
        Builtins.y2debug("cur=%1", cur)

        if cur != :custom
          if current != cur
            Builtins.y2debug("Level modified (%1)", cur)
            Security.Settings = Ops.get(@Levels, Convert.to_string(cur), {})
            Security.modified = true
          end
          ret = :finish if ret == :next
        end
      end

      deep_copy(ret)
    end
  end
end
