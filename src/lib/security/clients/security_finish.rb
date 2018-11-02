# encoding: utf-8

# ------------------------------------------------------------------------------
# Copyright (c) 2018 SUSE LLC
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of version 2 of the GNU General Public License as published by the
# Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# ------------------------------------------------------------------------------

require "installation/finish_client"

module Yast
  class SecurityFinishClient < ::Installation::FinishClient
    include Logger

    def initialize
      textdomain "security"

      Yast.import "Security"
    end

    # Write users
    #
    def write
      Security.Write      
    end

  protected

    # @see Implements ::Installation::FinishClient#modes
    def modes
      # Security module has no proposal or configuration while a
      # normal installation. So only AutoYaST installation is for interest.
      [:autoinst]
    end

    # @see Implements ::Installation::FinishClient#title
    def title
      _("Writing Security Configuration...")
    end
  end
end
