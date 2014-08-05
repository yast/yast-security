#!/usr/bin/env rspec

require 'rspec'
ENV["Y2DIR"] = File.expand_path("../../src", __FILE__)
require "yast"

def services_for(names)
  names.map {|n| Yast::DummySystemdUnit.new(n) }
end

module Yast
  # SystemdUnit is 'too smart' for our testing purposes
  class DummySystemdUnit
    attr_accessor :name

    def initialize(name)
      self.name = name
    end

    def enabled?; true; end
  end

  import "Security"

  describe Security do
    describe "#ReadServiceSettings" do

      before(:each) do 
        allow(SystemdService).to receive(:all).and_return services_for(service_names)
        Security.ReadServiceSettings
      end

      context "only with mandatory services" do
        let(:service_names) { %w(ntp syslog auditd random kbd cron postfix sendmail) }

        it "sets settings for all runlevels to 'secure'" do
          expect(Security.Settings["RUNLEVEL3_MANDATORY_SERVICES"]).to eq("secure")
          expect(Security.Settings["RUNLEVEL5_MANDATORY_SERVICES"]).to eq("secure")
          expect(Security.Settings["RUNLEVEL3_EXTRA_SERVICES"]).to eq("secure")
          expect(Security.Settings["RUNLEVEL5_EXTRA_SERVICES"]).to eq("secure")
        end
      end

      context "with mandatory and extra services" do
        let(:service_names) { %w(ntp syslog auditd random kbd extra1 cron postfix sendmail) }

        it "sets settings for extra services as 'insecure'" do
          expect(Security.Settings["RUNLEVEL3_MANDATORY_SERVICES"]).to eq("secure")
          expect(Security.Settings["RUNLEVEL5_MANDATORY_SERVICES"]).to eq("secure")
          expect(Security.Settings["RUNLEVEL3_EXTRA_SERVICES"]).to eq("insecure")
          expect(Security.Settings["RUNLEVEL5_EXTRA_SERVICES"]).to eq("insecure")
        end
      end

      context "without all mandatory services and extra ones" do
        let(:service_names) { %w(ntp syslog auditd extra1 cron postfix sendmail) }

        it "sets settings for all runlevels to 'insecure'" do
          expect(Security.Settings["RUNLEVEL3_MANDATORY_SERVICES"]).to eq("insecure")
          expect(Security.Settings["RUNLEVEL5_MANDATORY_SERVICES"]).to eq("insecure")
          expect(Security.Settings["RUNLEVEL3_EXTRA_SERVICES"]).to eq("insecure")
          expect(Security.Settings["RUNLEVEL5_EXTRA_SERVICES"]).to eq("insecure")
        end
      end

      context "with no services" do
        let(:service_names) { [] }

        it "sets settings for mandatory to 'insecure'" do
          expect(Security.Settings["RUNLEVEL3_MANDATORY_SERVICES"]).to eq("insecure")
          expect(Security.Settings["RUNLEVEL5_MANDATORY_SERVICES"]).to eq("insecure")
          expect(Security.Settings["RUNLEVEL3_EXTRA_SERVICES"]).to eq("secure")
          expect(Security.Settings["RUNLEVEL5_EXTRA_SERVICES"]).to eq("secure")
        end
      end
    end
  end
end
