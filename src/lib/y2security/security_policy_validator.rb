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

module Y2Security
  class SecurityPolicyValidator
    include Yast::Logger

    class << self
      # Returns a validator for the given policy
      #
      # @fixme should we allow an id?
      #
      # @param [SecurityPolicy] Security policy to build the validator for
      def for(policy)
        require "y2security/#{policy.id}_validator"
        klass = Module.const_get("Y2Security::#{policy.id.capitalize}Validator")
        klass.new
      rescue LoadError, NameError => e
        log.info "Could not load a validator for #{policy}: #{e.message}"
      end
    end

    # Returns the issues found for the given scope
    #
    # @param scope [Symbol] Scope to validate (:network, :storage, :bootloader, etc.)
    def issues(_scope); end
  end
end
