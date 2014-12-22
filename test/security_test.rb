#!/usr/bin/env rspec

ENV["Y2DIR"] = File.expand_path("../../src", __FILE__)
DATA_PATH = File.join(File.expand_path(File.dirname(__FILE__)), "data")

require 'rspec'
require "yast"
require_relative 'SCRStub'

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

  RSpec.configure do |c|
    c.include SCRStub
  end

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

    describe "#Write" do
      it "writes and applies all the settings" do
        expect(Security).to receive(:write_to_locations)
        expect(Security).to receive(:write_console_shutdown)
        expect(Security).to receive(:write_pam_settings)
        expect(Security).to receive(:write_polkit_settings)
        expect(Security).to receive(:write_kernel_settings)
        expect(Security).to receive(:apply_new_settings)
        expect(Security).to receive(:activate_changes)
        Security.modified = true
        Security.Write
      end
    end

    describe "#write_to_locations" do
      before do
        set_root_path(File.join(DATA_PATH, "system"))
        Security.read_from_locations
        stub_scr_write
      end

      after do
        reset_root_path
      end

      it "does not write nil values" do
        expect(SCR).to_not receive(:Write).
          with(path(".sysconfig.mail.SMTPD_LISTEN_REMOTE"), anything)

        Security.Settings["SMTPD_LISTEN_REMOTE"] = nil
        Security.write_to_locations
      end

      it "does not write unchanged values" do
        expect(SCR).to_not receive(:Write).
          with(path(".sysconfig.mail.SMTPD_LISTEN_REMOTE"), anything)

        Security.Settings["SMTPD_LISTEN_REMOTE"] = "no"
        Security.write_to_locations
      end

      it "adds missing values" do
        Security.Settings["DISPLAYMANAGER_SHUTDOWN"] = "yes"
        Security.write_to_locations

        expect(written_value_for(".sysconfig.displaymanager.DISPLAYMANAGER_SHUTDOWN")).
          to eq("yes")
        expect(was_written?(".sysconfig.displaymanager")).to eq(true)
      end

      it "updates changed values" do
        Security.Settings["USERADD_CMD"] = "cmd"
        Security.Settings["USERDEL_PRECMD"] = ""
        Security.write_to_locations

        expect(written_value_for(".etc.login_defs.USERADD_CMD")).to eq("cmd")
        expect(written_value_for(".etc.login_defs.USERDEL_PRECMD")).to eq("")
        expect(was_written?(".etc.login_defs")).to eq(true)
      end
    end

    describe "#write_kernel_settings" do
      before do
        set_root_path(File.join(DATA_PATH, "system"))
        Security.read_kernel_settings
        stub_scr_write
      end

      after do
        reset_root_path
      end

      context "writing to sysctl.conf" do
        before do
          allow(SCR).to exec_bash(/echo .* \/kernel\/sysrq/)
        end

        it "does not write invalid values" do
          expect(SCR).to_not receive(:Write)

          Security.Settings["kernel.sysrq"] = "yes"
          Security.Settings["net.ipv4.ip_forward"] = ""
          Security.write_kernel_settings
        end

        it "does not write unchanged values" do
          expect(SCR).to_not receive(:Write)

          Security.Settings["net.ipv4.ip_forward"] = "0"
          Security.write_kernel_settings
        end

        it "writes changed values" do
          Security.Settings["net.ipv4.ip_forward"] = "1"
          Security.write_kernel_settings

          expect(written_value_for(".etc.sysctl_conf.net.ipv4.ip_forward")).
            to eq("1")
          expect(was_written?(".etc.sysctl_conf")).to eq(true)
        end
      end

      context "setting sysrq" do
        it "does not write invalid values" do
          expect(SCR).to_not exec_bash(/echo .* \/kernel\/sysrq/)

          Security.Settings["kernel.sysrq"] = "yes"
          Security.write_kernel_settings
        end

        it "writes valid values" do
          expect(SCR).to exec_bash("echo 1 > /proc/sys/kernel/sysrq")

          Security.Settings["kernel.sysrq"] = "1"
          Security.write_kernel_settings
        end
      end
    end
  end
end
