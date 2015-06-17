#!/usr/bin/env rspec

require_relative 'test_helper'

module Yast
  class LevelsTester < Client
    attr_reader :Levels

    def initialize
      Yast.import "Security"
      Yast.include self, "security/levels.rb"
    end

    def apply_level2
      Security.Settings = @Levels["Level2"]
      Security.modified = true
      Security.Write
    end
  end

  describe "Levels" do
    let(:tester) { LevelsTester.new }
    subject(:settings) { tester.Levels }

    it "reads the settings from the yaml files" do
      expect(settings["Level1"]["FAIL_DELAY"]).to eq "1"
      expect(settings["Level2"]["FAIL_DELAY"]).to eq "6"
      expect(settings["Level3"]["FAIL_DELAY"]).to eq "3"
    end

    # This 'describe' is the translation to RSpec of the former testsuite.
    # It's not exactly elegant, but it ensures we don't decrease the number of
    # covered scenarios by deleting the old testsuite.
    describe "together with Security" do
      before do
        change_scr_root(File.join(DATA_PATH, "system"))
        stub_scr_write
        allow(Package).to receive(:Installed).with("systemd").and_return true
      end

      after do
        reset_scr_root
      end

      # Not really needed, but looks better than returning nil
      let(:empty_bash_output) { {"exit" => 0, "stdout" => "", "stderr" => ""} }

      it "defines the system behavior" do
        expect(SCR).to exec_bash_output("/usr/sbin/pam-config -a --cracklib")
          .and_return(empty_bash_output)
        expect(SCR).to exec_bash_output("/usr/sbin/pam-config -d --cracklib-minlen")
          .and_return(empty_bash_output)
        expect(SCR).to exec_bash_output("/usr/sbin/pam-config -d --pwhistory-remember")
          .and_return(empty_bash_output)
        expect(SCR).to exec_bash("ln -s -f /dev/null /etc/systemd/system/ctrl-alt-del.target")
        expect(SCR).to exec_bash("echo 0 > /proc/sys/kernel/sysrq")
        expect(SCR).to exec_bash("/usr/bin/chkstat --system")

        tester.apply_level2

        expect(written_value_for(".etc.login_defs.FAIL_DELAY")).to eq "6"
        expect(written_value_for(".sysconfig.locate.RUN_UPDATEDB_AS")).to eq "nobody"
      end
    end
  end
end
