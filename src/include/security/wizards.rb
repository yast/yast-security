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

# File:	include/security/wizards.ycp
# Package:	Security configuration
# Summary:	Wizards definitions
# Authors:	Michal Svec <msvec@suse.cz>
#
# $Id$
module Yast
  module SecurityWizardsInclude
    def initialize_security_wizards(include_target)
      Yast.import "UI"

      textdomain "security"

      Yast.import "Label"
      Yast.import "Sequencer"
      Yast.import "Wizard"

      Yast.include include_target, "security/complex.rb"
      Yast.include include_target, "security/dialogs.rb"
      Yast.include include_target, "security/users.rb"
    end

    def TreeDialog
      Wizard.OpenTreeNextBackDialog
      tree = []

      # params: input tree, parent, label, id
      tree = Wizard.AddTreeItem(tree, "", _("Security Overview"), "overview")
      tree = Wizard.AddTreeItem(
        tree,
        "",
        _("Predefined Security Configurations"),
        "main"
      )
      tree = Wizard.AddTreeItem(tree, "", _("Password Settings"), "password")
      tree = Wizard.AddTreeItem(tree, "", _("Boot Settings"), "boot")
      tree = Wizard.AddTreeItem(tree, "", _("Login Settings"), "login")
      tree = Wizard.AddTreeItem(tree, "", _("User Addition"), "users")
      tree = Wizard.AddTreeItem(tree, "", _("Miscellaneous Settings"), "misc")

      Wizard.CreateTree(tree, _("Security"))

      ret = OverviewDialog()

      while true
        # needed for ncurses UI
        ret = Wizard.QueryTreeItem if ret == :wizardTree

        if ret == "main"
          ret = MainDialog()
        elsif ret == "overview"
          ret = OverviewDialog()
        elsif ret == "password"
          ret = PassDialog()
        elsif ret == "boot"
          ret = BootDialog()
        elsif ret == "login"
          ret = LoginDialog()
        elsif ret == "users"
          ret = AdduserDialog()
        elsif ret == "misc"
          ret = MiscDialog()
        elsif ret == :next || ret == :abort || ret == :finish
          break
        else
          Builtins.y2error("Unknown return value %1, aborting...", ret)
          ret = :abort
          break
        end
      end

      Wizard.CloseDialog

      deep_copy(ret)
    end

    # Main workflow of the security configuration
    # @return [Object] Returned value from WizardSequencer() call
    def MainSequence
      aliases = {
        "main"     => lambda { MainDialog() },
        "password" => lambda { PassDialog() },
        "boot"     => lambda { BootDialog() },
        "login"    => lambda { LoginDialog() },
        "adduser"  => lambda { AdduserDialog() },
        "misc"     => lambda { MiscDialog() }
      }

      sequence = {
        "ws_start" => "main",
        "main"     => {
          :abort  => :abort,
          :next   => "password",
          :finish => :next
        },
        "password" => { :abort => :abort, :next => "boot" },
        "boot"     => { :abort => :abort, :next => "login" },
        "login"    => { :abort => :abort, :next => "adduser" },
        "adduser"  => { :abort => :abort, :next => "misc" },
        "misc"     => { :abort => :abort, :next => :next }
      }

      ret = Sequencer.Run(aliases, sequence)

      deep_copy(ret)
    end

    # Whole configuration of security
    # @return [Object] Returned value from WizardSequencer() call
    def SecuritySequence
      aliases = { "main" => lambda { TreeDialog() }, "write" => [lambda do
        WriteDialog()
      end, true] }

      sequence = {
        "ws_start" => "main",
        "main"     => { :abort => :abort, :finish => "write", :next => "write" },
        "write"    => { :abort => :abort, :next => :next }
      }

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("security")

      # Read has no progress and returns only true
      Security.Read

      ret = Sequencer.Run(aliases, sequence)

      UI.CloseDialog
      deep_copy(ret)
    end

    # Whole configuration of security but without reading and writing.
    # For use with autoinstallation.
    # @return [Object] Returned value from WizardSequencer() call
    def SecurityAutoSequence
      # Dialog caption
      caption = _("Security Configuration")
      # Label
      contents = Label(_("Initializing..."))

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("security")
      Wizard.SetContentsButtons(
        caption,
        contents,
        "",
        Label.BackButton,
        Label.NextButton
      )

      # Run the main configuration workflow
      ret = TreeDialog()

      UI.CloseDialog
      deep_copy(ret)
    end
  end
end
