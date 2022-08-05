# Copyright (c) [2022] SUSE LLC
#
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of version 2 of the GNU General Public License as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, contact SUSE LLC.
#
# To contact SUSE LLC about this file by physical or electronic mail, you may
# find current contact information at www.suse.com.

require "yast"
require "y2issues/list"
require "singleton"

module Y2Security
  # List of security policy issues
  class SecurityPolicyIssues < Y2Issues::List
    def update(issues)
      scopes = issues.map { |i| i.location&.path }.compact
      other_issues = @items.reject do |item|
        scopes.include?(item.location&.path)
      end

      @items = other_issues + issues.to_a
    end
  end
end
