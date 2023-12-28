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

# File:	include/security/routines.ycp
# Module:	Security configuration
# Summary:	Routines
# Authors:	Michal Svec <msvec@suse.cz>
#
# $Id$
#
# These functions are used for the user interface creation
# and interaction.
# <pre>
# Usage:
#   include "security/ui.ycp";
#   map WIDGETS = CallFunction(`your_widgets());
# </pre>
module Yast
  module SecurityRoutinesInclude
    def initialize_security_routines(include_target)
      Yast.import "UI"

      textdomain "security"

      Yast.import "Popup"
      Yast.import "Security"

      Yast.include include_target, "security/widgets.rb"
    end

    # Vertical separator
    # @return vertical separator
    def VSeparator
      VSpacing(Opt(:vstretch), 0.1)
    end

    # Horizontal separator
    # @return horizontal separator
    def HSeparator
      HSpacing(Opt(:hstretch), 0.1)
    end

    # Return a widget from the WIDGETS map created acording to the ID.
    # @param [String] widget_id security setting identifier
    # @return created widget
    # @see <a href="widgets.html">widgets.ycp</a>
    def settings2widget(widget_id)
      m = Ops.get_map(@WIDGETS, widget_id, {})
      label = Ops.get_string(m, "Label", "")
      widget = Ops.get_string(m, "Widget", "")
      value = Ops.get(Security.Settings, widget_id, "")
      minval = Ops.get_integer(m, "MinValue", 0)
      maxval = Ops.get_integer(m, "MaxValue", 2147483647)

      # "Widget" == "CheckBox"
      if widget == "CheckBox"
        enabled = false
        enabled = true if value == "yes"
        chbox = CheckBox(Id(widget_id), label, enabled)
        if Ops.get_string(m, "Notify", "no") == "yes"
          chbox = CheckBox(Id(widget_id), Opt(:notify), label, enabled)
        end
        return VBox(Left(chbox), VSeparator())
      end

      # "Widget" == "TextEntry"
      if widget == "TextEntry"
        return VBox(Left(TextEntry(Id(widget_id), label, value)), VSeparator())
      end

      # "Widget" == "IntField"
      if widget == "IntField"
        intval = Builtins.tointeger(value)
        intval = 0 if intval == nil
        return VBox(
          Left(IntField(Id(widget_id), label, minval, maxval, intval)),
          VSeparator()
        )
      end

      # "Widget" == "???"
      if widget != "ComboBox"
        Builtins.y2error("Unknown widget: %1", widget)
        return VSeparator()
      end

      # "Widget" == "ComboBox"
      li = Ops.get_list(m, "Options", [])
      combo = []
      i = 0
      selected = false

      while Ops.less_than(i, Builtins.size(li))
        # string|list it
        Builtins.y2debug("li=%1 (%2)", li, i)
        it = Ops.get(li, i)
        it = "" if it == nil
        Builtins.y2debug("it=%1", it)
        id_t = ""
        id_s = ""
        if Ops.is_string?(it)
          id_t = Convert.to_string(it)
          id_s = Convert.to_string(it)
        else
          it_list = Convert.convert(it, from: "any", to: "list <string>")

          id_t = Ops.get(it_list, 0, "")
          id_s = Ops.get(it_list, 1, "")
        end
        if value == id_t
          combo = Builtins.add(combo, Item(Id(id_t), id_s, true))
          selected = true
        else
          combo = Builtins.add(combo, Item(Id(id_t), id_s))
        end
        i = Ops.add(i, 1)
      end
      if !selected && Ops.get_string(m, "Editable", "no") == "yes"
        combo = Builtins.add(combo, Item(Id(value), value, true))
      end

      opt_t = nil
      opt_t = Opt(:editable) if Ops.get_string(m, "Editable", "no") == "yes"
      if Ops.get_string(m, "Notify", "no") == "yes"
        opt_t = opt_t == nil ? Opt(:notify) : Builtins.add(opt_t, :notify)
      end
      combobox = if opt_t == nil
        ComboBox(Id(widget_id), label, combo)
      else
        ComboBox(Id(widget_id), opt_t, label, combo)
      end

      VBox(Left(combobox), VSeparator())
    end

    # Query the widget with `id(id) for its `Value
    # @param [String] id security setting identifier
    def widget2settings(id)
      ret = UI.QueryWidget(Id(id), :Value)
      new = ""
      if Ops.is_boolean?(ret)
        new = ret ? "yes" : "no"
      elsif Ops.is_integer?(ret)
        new = Builtins.sformat("%1", ret)
      elsif Ops.is_string?(ret)
        new = Convert.to_string(ret)
      else
        Builtins.y2error("Unknown widget type: %1", ret)
        new = nil
      end

      if !new.nil? && Ops.get(Security.Settings, id, "") != new
        Builtins.y2milestone(
          "Setting modified (%1): %2 -> %3)",
          id,
          Ops.get(Security.Settings, id, ""),
          new
        )
        Ops.set(Security.Settings, id, new)
        Security.modified = true
      end

      nil
    end

    # Frame with spacings
    # @param [Float] f1 horizontal spacing
    # @param [Float] f2 vertical spacing
    # @param [String] label frame label
    # @param [Yast::Term] content frame contents
    # @return frame with contents
    def XFrame(f1, f2, label, content)
      Frame(
        label,
        HBox(HSpacing(f1), VBox(VSpacing(f2), content, VSpacing(f2)), HSpacing(f1))
      )
    end

    # Check if minimum is less than maximum in the widget
    # @param [String] minID ID os the minimum widget
    # @param [String] maxID ID os the maximum widget
    # @return true or false
    def checkMinMax(minID, maxID)
      min = UI.QueryWidget(Id(minID), :Value)
      max = UI.QueryWidget(Id(maxID), :Value)
      if (Ops.is_integer?(min) || Ops.is_float?(min)) &&
          (Ops.is_integer?(max) || Ops.is_float?(max)) &&
          Ops.less_or_equal(min, max)
        return true
      end

      false
    end

    # If modified, ask for confirmation
    # @return true if abort is confirmed
    def ReallyAbort
      !Security.Modified || Popup.ReallyAbort(true)
    end
  end
end
