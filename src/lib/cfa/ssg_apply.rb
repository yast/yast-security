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
  #   file.remediation = "/usr/share/scap-security-guide/bash/sle15-script-stig.sh"
  #   file.disabled_rules = ["partition_for_home"]
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
      profile: "profile", remediation: "remediation", disabled_rules: "disabled-rules"
    )

    class << self
      # Loads a file
      #
      # @param file_handler [#read,#write] an object able to read/write a string (like File)
      # @param file_path    [String] File path
      # @return [SsgApply] File with the already loaded content
      def load(file_handler: Yast::TargetFile, file_path: PATH)
        file = new(file_handler: file_handler, file_path: file_path)
        file.load
        file
      rescue Errno::ENOENT
        log.info("#{file_path} couldn't be loaded. Probably the file does not exist yet.")

        file
      end
    end

    # @param file_handler [#read,#write] an object able to read/write a string (like File)
    # @param file_path    [String] File path
    def initialize(file_handler: Yast::TargetFile, file_path: PATH)
      super(AugeasParser.new(LENS), file_path, file_handler: file_handler)
    end

    # Removes empty values before saving, otherwise the lens complains
    def save
      matcher = CFA::Matcher.new { |_, v| v.strip.empty? }
      empty_elements = data.select(matcher).map { |e| e[:key] }
      empty_elements.each { |e| data.delete(e) }
      super
    end

    # Returns the list of disabled rules
    #
    # To add rules to the list, please use the #disabled_rules= method instead of
    # adding rules to the value returned by this method.
    #
    # @return [Array<String>] List of disabled rules
    def disabled_rules
      @disabled_rules ||= generic_get("disabled-rules")
        .to_s.split(",").freeze
    end

    # Sets the list of disabled rules
    #
    # @example Adding disabled rules
    #   file = SsgApply.load
    #   rules = file.disabled_rules
    #   new_rule = Rule.new("SLES-15-000000", "My dummy rule", :unknown)
    #   file.disabled_rules = rules + [new_rule]
    #
    # @param value [Array<String>] List of disabled rules IDs
    def disabled_rules=(value)
      @disabled_rules = nil
      generic_set("disabled-rules", value.join(","))
    end

    # Determines whether the file is empty
    #
    # @return [Boolean] true if it is empty; false otherwise
    def empty?
      data.data.empty?
    end
  end
end
