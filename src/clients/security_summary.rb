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

# File:	clients/security_summary.ycp
# Package:	Security configuration
# Summary:	Securitys summary
# Authors:	Michal Svec <msvec@suse.cz>
#
# $Id$
module Yast
  class SecuritySummaryClient < Client
    def main
      textdomain "security"

      Yast.import "Progress"
      Yast.import "Security"
      Yast.import "Summary"

      # The main ()
      Builtins.y2milestone("----------------------------------------")
      Builtins.y2milestone("Security summary started")

      Progress.off
      Security.Read
      @sum = Security.Summary
      Builtins.y2debug("summary=%1", @sum)
      @ret = Ops.get_string(@sum, 0, "")
      Progress.on

      # Finish
      Builtins.y2milestone("Security summary finished")
      Builtins.y2milestone("----------------------------------------")
      @ret 

      # EOF
    end
  end
end

Yast::SecuritySummaryClient.new.main
