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
  class Level1Client < Client
    def main
      Yast.include self, "testsuite.rb"

      Yast.import "Security"
      Yast.include self, "security/levels.rb"

      @E = { "target" => { "bash_output" => {} } }
      @R = {
        "sysconfig" => { "displaymanager" => { "DISPLAYMANAGER" => "" } },
        "target"    => {
          # FileUtils::Exists returns true:
          "stat" => { 1 => 2 }
        }
      }

      Security.Settings = Ops.get(@Levels, "Level1", {})
      Security.modified = true
      TEST(lambda { Security.Write }, [@R, {}, @E], nil)

      nil
    end
  end
end

Yast::Level1Client.new.main
