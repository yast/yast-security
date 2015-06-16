#!/usr/bin/env rspec

require_relative 'test_helper'

module Yast
  class LevelsTester
    include Yast::I18n

    attr_reader :Levels

    def initialize
      Yast.include self, "security/levels.rb"
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
  end
end
