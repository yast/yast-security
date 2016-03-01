#!/usr/bin/env rspec

require_relative "test_helper"
require "security/ctrl_alt_del_config"

def services_for(names, aliases = {})
  names.map do |n|
    if aliases[n]
      Yast::DummySystemdUnit.new(n, aliases[n])
    else
      Yast::DummySystemdUnit.new(n)
    end
  end
end

module Yast
  # SystemdUnit is 'too smart' for our testing purposes
  class DummySystemdUnit
    attr_accessor :name, :properties

    Struct.new("DummyProperties", :names)

    def initialize(name, aliases = nil)
      self.name = name
      self.properties = Struct::DummyProperties.new(aliases)
    end

    def enabled?
      true
    end
  end

  import "Security"
  import "SystemdService"
  import "Service"

  describe Security do
    describe "#ReadServiceSettings" do
      let(:aliases) { {} }

      before(:each) do
        allow(Service).to receive(:enabled?) do |service|
          service_names.include?(service)
        end
        allow(SystemdService).to receive(:all).and_return services_for(service_names, aliases)
        Security.ReadServiceSettings
      end

      context "only with mandatory services" do
        let(:service_names) { %w(apparmor auditd SuSEfirewall2 wicked) }

        it "sets settings for services as 'secure'" do
          expect(Security.Settings["MANDATORY_SERVICES"]).to eq("secure")
          expect(Security.Settings["EXTRA_SERVICES"]).to eq("secure")
        end
      end

      context "with mandatory and extra services" do
        let(:service_names) { %w(apparmor auditd SuSEfirewall2 extra1 wicked) }

        it "sets settings for extra services as 'insecure'" do
          expect(Security.Settings["MANDATORY_SERVICES"]).to eq("secure")
          expect(Security.Settings["EXTRA_SERVICES"]).to eq("insecure")
        end
      end

      context "without all mandatory services and extra ones" do
        let(:service_names) { %w(auditd shorewall extra1 wicked) }

        it "sets settings for services as 'insecure'" do
          expect(Security.Settings["MANDATORY_SERVICES"]).to eq("insecure")
          expect(Security.Settings["EXTRA_SERVICES"]).to eq("insecure")
        end
      end

      context "with services that are aliases of optional services" do
        let(:service_names) { %w(apparmor auditd anacron firewalld wicked rsyslog) }
        let(:aliases) do
          { "rsyslog" => "rsyslog.service syslog.service", "anacron" => "anacron cron" }
        end

        it "sets settings for extra services as 'secure'" do
          expect(Security.Settings["EXTRA_SERVICES"]).to eq("secure")
        end
      end

      context "with no services" do
        let(:service_names) { [] }

        it "sets settings for mandatory to 'insecure'" do
          expect(Security.Settings["MANDATORY_SERVICES"]).to eq("insecure")
          expect(Security.Settings["EXTRA_SERVICES"]).to eq("secure")
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
        change_scr_root(File.join(DATA_PATH, "system"))
        Security.read_from_locations
        stub_scr_write
      end

      after do
        reset_scr_root
      end

      it "does not write nil values" do
        expect(SCR).to_not receive(:Write)
          .with(path(".sysconfig.mail.SMTPD_LISTEN_REMOTE"), anything)

        Security.Settings["SMTPD_LISTEN_REMOTE"] = nil
        Security.write_to_locations
      end

      it "does not write unchanged values" do
        expect(SCR).to_not receive(:Write)
          .with(path(".sysconfig.mail.SMTPD_LISTEN_REMOTE"), anything)

        Security.Settings["SMTPD_LISTEN_REMOTE"] = "no"
        Security.write_to_locations
      end

      it "adds missing values" do
        Security.Settings["AllowShutdown"] = "Root"
        Security.write_to_locations

        expect(written_value_for(".kde4.kdmrc.AllowShutdown"))
          .to eq("Root")
        expect(was_written?(".kde4.kdmrc")).to eq(true)
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
        change_scr_root(File.join(DATA_PATH, "system"))
        Security.read_kernel_settings
        stub_scr_write
      end

      after do
        reset_scr_root
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

          expect(written_value_for(".etc.sysctl_conf.net.ipv4.ip_forward"))
            .to eq("1")
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

    describe "#ReadConsoleShutdown" do
      let(:ctrl_alt_del_file) { "/etc/systemd/system/ctrl-alt-del.target" }
      let(:target_link) { "/usr/lib/systemd/system/poweroff.target" }

      context "when systemd is installed" do

        context "on a non s390 architecture" do
          before do
            allow(Arch).to receive(:s390) { false }
          end

          context "when ctrl+alt+del file not exist" do
            it "returns 'reboot'" do
              allow(FileUtils).to receive(:Exists).with(ctrl_alt_del_file) { false }

              expect(Security.ReadConsoleShutdown).to eql("reboot")
            end
          end

          context "when ctrl+del+alt file exist" do
            before do
              allow(FileUtils).to receive(:Exists).with(ctrl_alt_del_file) { true }
            end

            it "returns 'ignore' by default" do
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return("dummy_file")

              expect(Security.ReadConsoleShutdown).to eql("ignore")
            end

            it "returns 'halt' if links to poweroff.target" do
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return(target_link)

              expect(Security.ReadConsoleShutdown).to eql("halt")
            end

            it "returns 'reboot' if links to reboot.target" do
              target_link = "/usr/lib/systemd/system/reboot.target"
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return(target_link)

              expect(Security.ReadConsoleShutdown).to eql("reboot")
            end

            it "returns 'reboot' if links to ctrl-alt-del.target" do
              target_link = "/usr/lib/systemd/system/ctrl-alt-del.target"
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return(target_link)

              expect(Security.ReadConsoleShutdown).to eql("reboot")
            end

          end
        end

        context "on a s390 architecture" do
          before do
            allow(Arch).to receive(:s390) { true }
          end

          context "when ctrl+alt+del file not exist" do
            it "returns 'reboot'" do
              allow(FileUtils).to receive(:Exists).with(ctrl_alt_del_file) { false }

              expect(Security.ReadConsoleShutdown).to eql("halt")
            end
          end

          context "when ctrl+del+alt file exist" do
            before do
              allow(FileUtils).to receive(:Exists).with(ctrl_alt_del_file) { true }
            end

            it "returns 'ignore' by default" do
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return("dummy_file")

              expect(Security.ReadConsoleShutdown).to eql("ignore")
            end

            it "returns 'halt' if links to poweroff.target" do
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return(target_link)

              expect(Security.ReadConsoleShutdown).to eql("halt")
            end

            it "returns 'reboot' if links to reboot.target" do
              target_link = "/usr/lib/systemd/system/reboot.target"
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return(target_link)

              expect(Security.ReadConsoleShutdown).to eql("reboot")
            end

            it "returns 'halt' if links to ctrl-alt-del.target" do
              target_link = "/usr/lib/systemd/system/ctrl-alt-del.target"
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return(target_link)

              expect(Security.ReadConsoleShutdown).to eql("halt")
            end

          end
        end
      end

      context "when systemd is not installed but inittab exist" do
        before do
          allow(Package).to receive(:Installed).with("systemd") { false }
        end

        it "always returns nil" do
          allow(FileUtils).to receive(:Exists).with("/etc/inittab")
            .and_return(false, true)
          allow(::Security::CtrlAltDelConfig).to receive(:current)
            .and_return("reboot", "halt")

          expect(Security.ReadConsoleShutdown).to eql(nil)
          expect(Security.ReadConsoleShutdown).to eql(nil)
        end

        context "on a non s390 architecture" do
          before do
            allow(Arch).to receive(:s390) { false }
            allow(::Security::CtrlAltDelConfig).to receive(:inittab?) { true }
          end

          context "when no inittab ca entry" do
            it "returns 'reboot'" do
              allow(FileUtils).to receive(:Exists).with("/etc/inittab") { false }

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eq("reboot")
            end
          end

          context "when inittab ca entry exist" do
            before do
              allow(FileUtils).to receive(:Exists).with("/etc/inittab") { true }
            end

            it "sets settings for shutdown as 'ignore' by default" do
              allow(SCR).to receive(:Read).with(path(".etc.inittab.ca"))
                .and_return("12345:ctrlaltdel:/bin/false")

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eq("ignore")
            end

            it "sets settings for shutdown as 'halt' if contains 'halt' or ' -h'" do
              allow(SCR).to receive(:Read).with(path(".etc.inittab.ca"))
                .and_return("12345:ctrlaltdel:/sbin/shutdown -h now")

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eq("halt")
            end

            it "sets settings for shutdown as 'reboot' if contains 'reboot' or -r" do
              allow(SCR).to receive(:Read).with(path(".etc.inittab.ca"))
                .and_return("12345:ctrlaltdel:/sbin/shutdown -r now")

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eq("reboot")
            end

          end
        end

        context "on a s390 architecture" do
          before do
            allow(Arch).to receive(:s390) { true }
            allow(::Security::CtrlAltDelConfig).to receive(:inittab?) { true }
          end

          context "when no inittab ca entry" do
            it "returns 'halt'" do
              allow(FileUtils).to receive(:Exists).with("/etc/inittab") { false }

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eq("halt")
            end
          end

          context "when inittab ca entry exist" do
            before do
              allow(FileUtils).to receive(:Exists).with("/etc/inittab") { true }
            end

            it "sets settings for shutdown as 'ignore' by default" do
              allow(SCR).to receive(:Read).with(path(".etc.inittab.ca"))
                .and_return("12345:ctrlaltdel:/bin/echo 'Not implemented'")

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eq("ignore")
            end

            it "sets settings for shutdown as 'halt' if contains 'halt' or ' -h'" do
              allow(SCR).to receive(:Read).with(path(".etc.inittab.ca"))
                .and_return("12345:/sbin/shutdown -h now")

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eq("halt")
            end

            it "sets settings for shutdown as 'reboot' if contains 'reboot' or -r" do
              allow(SCR).to receive(:Read).with(path(".etc.inittab.ca"))
                .and_return("12345:ctrlaltdel:/sbin/shutdown -r now")

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eq("reboot")
            end

          end
        end
      end
    end

    describe "#read_permissions" do

      context "depending on current persission" do
        it "sets security permission to 'easy' if contains easy" do
          Security.Settings["PERMISSION_SECURITY"] = "it_is_easy_to_test"

          expect(Security.read_permissions).to eql("easy")
          expect(Security.Settings["PERMISSION_SECURITY"]).to eql("easy")
        end

        it "sets security permission to 'paranoid' if contains paranoid" do
          Security.Settings["PERMISSION_SECURITY"] = "paranoid_permission"

          expect(Security.read_permissions).to eql("paranoid")
          expect(Security.Settings["PERMISSION_SECURITY"]).to eql("paranoid")
        end

        it "sets secure by default" do
          Security.Settings["PERMISSION_SECURITY"] = nil

          expect(Security.read_permissions).to eql("secure")
          expect(Security.Settings["PERMISSION_SECURITY"]).to eql("secure")
        end
      end

      describe "#read_hibernate_settings" do

      end
    end
  end
end
