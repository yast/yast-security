# Copyright (c) [2021] SUSE LLC
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
require "cfa/base_model"
require "yast2/target_file"

module CFA
  # CFA based class to handle the SELinux configuration file
  #
  # @example Reading a value
  #   file = CFA::Selinux.new
  #   file.load
  #   file.selinux #=> "enforcing"
  #
  # @example Writing a value
  #   file = CFA::Selinux.new
  #   file.selinux = "permissive"
  #   file.save
  #
  # @example Loading shortcut
  #   file = CFA::Selinux.load
  #   file.selinux #=> "enforcing"
  class Selinux < BaseModel
    attributes(
      selinux: "SELINUX"
    )

    # Instantiates and loads a file
    #
    # This method is basically a shortcut to instantiate and load the content in just one call.
    #
    # @param file_handler [#read,#write] something able to read/write a string (like File)
    # @param file_path    [String] File path
    # @return [Selinux] File with the already loaded content
    def self.load(file_handler: Yast::TargetFile, file_path: PATH)
      new(file_path: file_path, file_handler: file_handler).tap(&:load)
    end

    # Constructor
    #
    # @param file_handler [#read,#write] something able to read/write a string (like File)
    # @param file_path    [String] File path
    #
    # @see CFA::BaseModel#initialize
    def initialize(file_handler: Yast::TargetFile, file_path: PATH)
      super(AugeasParser.new(LENS), file_path, file_handler: file_handler)
    end

    private

    # Default path to the SELinux config file
    PATH = "/etc/selinux/config".freeze
    private_constant :PATH

    # The lens to be used by Augeas parser
    #
    # @note uses the simplevars lens instead of semanage because the latest is only available from
    #   augeas-lenses >= 1.12. See https://github.com/hercules-team/augeas/pull/594/files
    LENS = "simplevars.lns".freeze
    private_constant :LENS
  end
end
