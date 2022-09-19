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
require "cfa/base_model"
require "yast2/target_file"

module CFA
  # CFA-based class to handle the ssg-apply configuration file
  #
  # @example Writing the base configuration
  #   file = SsgApply.new
  #   file.profile = "disa_stig"
  #   file.disabled_rules = ["SLES-15-010190"]
  #   file.save
  #
  # @example Loading the configuration from a given file path
  #   file = SsgApply.new(file_path: "/etc/ssg-apply/default.conf")
  #   file.load
  #   file.profile #=> "stig"
  #   file.disabled_rules #=> []
  class SsgApply < BaseModel
    extend Yast::Logger
    include Yast::Logger

    PATH = "/etc/ssg-apply/override.conf".freeze
    LENS = "simplevars.lns".freeze
    private_constant :LENS

    attributes(
      profile: "profile", disabled_rules: "disabled-rules"
    )

    def initialize(file_handler: Yast::TargetFile, file_path: PATH)
      super(AugeasParser.new(LENS), file_path, file_handler: file_handler)
    end

    def disabled_rules
      @disabled_rules ||= generic_get("disabled-rules")
        .to_s.split(",").freeze
    end

    def disabled_rules=(value)
      @disabled_rules = nil
      generic_set("disabled-rules", value.join(","))
    end
  end
end
