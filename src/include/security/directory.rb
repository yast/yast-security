# encoding: utf-8

# ------------------------------------------------------------------------------
# Copyright (c) 2015 SUSE LLC. All Rights Reserved.
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
# this program; if not, contact SUSE, LLC.
#
# To contact SUSE about this file by physical or electronic mail, you may find
# current contact information at www.suse.com.
# ------------------------------------------------------------------------------

module Yast
  # Auxiliary module implementing an equivalent to
  # Yast::Directory.find_data_file, which is only available in more recent
  # versions of YaST
  module SecurityDirectoryInclude
    def initialize_security_directory(include_target)
    end

    # @see Yast::Directory.find_data_file (in yast2 >= 3.1.131)
    def find_data_file(relative_path)
       possible_paths = Yast.y2paths.map { |p| File.join(p, "data", relative_path) }
       possible_paths.find { |p| File.exist?(p) }
    end
  end
end
