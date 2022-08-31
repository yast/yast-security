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

module Y2Security
  module SecurityPolicies
    # Scopes for the validation of a security policy
    #
    # Scopes are used to check the policy rules associated to a specific area (e.g., network,
    # storage, etc). This is useful for clients that are interested in a subset of rules, for
    # example the storage rules in the Expert Partitioner.
    #
    # Note that there is no base class for scopes. For now there is nothing to share among them.
    # Moreover, the check code of the policies always knows what kind the scope it expects, so there
    # is no need of a common API for scopes.
    module Scopes
    end
  end
end

require "y2security/security_policies/scopes/storage"
require "y2security/security_policies/scopes/bootloader"
require "y2security/security_policies/scopes/network"
require "y2security/security_policies/scopes/firewall"
