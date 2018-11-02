#! /usr/bin/env rspec

require_relative "./test_helper"
require "security/clients/security_finish"
Yast.import "Security"

describe ::Yast::SecurityFinishClient do
  describe "#write" do
    it "writes security settings" do
      expect(::Yast::Security).to receive(:Write)

      subject.write
    end
  end
end
