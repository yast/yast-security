# encoding: utf-8

# YaST2: Modules testsuite
#
# Description:
#   Testsuite for the security module
#
# Authors:
#   Michal Svec <msvec@suse.cz>
#
# $Id$
#
# testedfiles: Security.ycp PamSettings.ycp Pam.ycp
module Yast
  class Level2Client < Client
    def main
      Yast.include self, "testsuite.rb"

      Yast.import "Security"
      Yast.include self, "security/levels.rb"

      @E = { "target" => { "bash_output" => {} } }
      @R = {
        "sysconfig" => { "displaymanager" => { "DISPLAYMANAGER" => "" } },
        "target"    => {
          # FileUtils::Exists returns false:
          "stat" => {}
        }
      }

      Security.Settings = Ops.get(@Levels, "Level2", {})
      Security.modified = true
      TEST(lambda { Security.Write }, [@R, {}, @E], nil)

      nil
    end
  end
end

Yast::Level2Client.new.main
