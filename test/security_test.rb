#!/usr/bin/env rspec

require_relative "test_helper"
require "yast2/systemd/service"
require "security/ctrl_alt_del_config"
require "security/display_manager"

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
  import "Service"

  describe Security do
    let(:sysctl_config) { CFA::SysctlConfig.new }
    let(:shadow_config) { CFA::ShadowConfig.new }
    let(:bash_path) { Yast::Path.new(".target.bash") }

    before do
      allow(CFA::SysctlConfig).to receive(:new).and_return(sysctl_config)
      allow(sysctl_config).to receive(:save)
      allow(CFA::ShadowConfig).to receive(:load).and_return(shadow_config)
      allow(shadow_config).to receive(:save)
      Security.main
    end

    describe "#ReadServiceSettings" do
      let(:aliases) { {} }

      before(:each) do
        allow(Service).to receive(:enabled?) do |service|
          service_names.include?(service)
        end
        allow(Yast2::Systemd::Service).to receive(:all).and_return services_for(service_names, aliases)
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
        expect(Security).to receive(:write_shadow_config)
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

    describe "#apply_new_settings" do
      before do
        allow(Security).to receive(:apply_sysctl_changes)
        allow(Yast::SCR).to receive(:Execute)
      end

      context "when the sysctl config is modified" do
        it "applies sysctl changes" do
          expect(Security).to receive(:apply_sysctl_changes)

          Security.apply_new_settings(sysctl: true)
        end
      end

      context "when the sysctl config is not modified" do
        it "does not apply sysctl changes" do
          expect(Security).to_not receive(:apply_sysctl_changes)

          Security.apply_new_settings
        end
      end

      it "applies all current permissions as they are now" do
        expect(Yast::SCR).to receive(:Execute)
          .with(bash_path, "/usr/bin/chkstat --system")

        Security.apply_new_settings
      end

      it "ensures polkit privileges are applied" do
        expect(FileUtils)
          .to receive(:Exists).with("/sbin/set_polkit_default_privs").and_return(true)
        expect(Yast::SCR).to receive(:Execute)
          .with(bash_path, "/sbin/set_polkit_default_privs")

        Security.apply_new_settings
      end
    end

    describe "#apply_sysctl_changes" do
      before do
        allow(Security).to receive(:sysctl_config).and_return(sysctl_config)
        allow(sysctl_config).to receive(:conflict?)
        allow(Yast::Execute).to receive(:on_target).with("/usr/sbin/sysctl", "--system")
      end

      it "checks if there are sysctl conflicts with other files" do
        expect(sysctl_config).to receive(:conflict?)

        Security.apply_sysctl_changes
      end

      it "applies the changes from all the configuration files" do
        expect(Yast::Execute).to receive(:on_target).with("/usr/sbin/sysctl", "--system")

        Security.apply_sysctl_changes
      end
    end

    describe "#write_to_locations" do
      before do
        change_scr_root(File.join(DATA_PATH, "system"))
        Security.init_settings
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
        Security.Settings["SYSTOHC"] = "yes"
        Security.write_to_locations

        expect(written_value_for(".sysconfig.clock.SYSTOHC")).to eq("yes")
        expect(was_written?(".sysconfig.clock")).to eq(true)
      end
    end

    describe "#write_shadow_config" do
      before do
        Security.Settings["FAIL_DELAY"] = "10"
      end

      it "writes login.defs configuration" do
        expect(shadow_config).to receive(:fail_delay=).with("10")
        expect(shadow_config).to receive(:save)
        Security.write_shadow_config
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
          allow(sysctl_config).to receive(:conflict?).and_return(false)
        end

        it "does not write invalid values" do
          Security.Settings["kernel.sysrq"] = "yes"
          Security.Settings["net.ipv4.ip_forward"] = ""
          expect(sysctl_config).to_not receive(:kernel_sysrq).with("yes")
          expect(sysctl_config).to_not receive(:raw_forward_ipv4=).with("")
          expect(Security.write_kernel_settings).to eq(false)
        end

        it "does not write unchanged values" do
          Security.Settings["net.ipv4.ip_forward"] = false
          expect(sysctl_config).to_not receive(:save)
          Security.write_kernel_settings
          expect(Security.write_kernel_settings).to eq(false)
        end

        it "writes changed values" do
          Security.Settings["net.ipv4.ip_forward"] = true
          expect(sysctl_config).to receive(:save)
          Security.write_kernel_settings
          expect(Security.write_kernel_settings).to eq(true)
        end
      end

      context "setting sysrq" do
        it "does not write invalid values" do
          Security.Settings["kernel.sysrq"] = "yes"
          expect(sysctl_config).to_not receive(:save)
          Security.write_kernel_settings
        end

        it "writes valid values" do
          Security.Settings["kernel.sysrq"] = "1"
          expect(sysctl_config).to receive(:save)
          Security.write_kernel_settings
        end
      end
    end

    describe "#ReadConsoleShutdown" do
      let(:ctrl_alt_del_file) { "/etc/systemd/system/ctrl-alt-del.target" }
      let(:target_link) { "/usr/lib/systemd/system/poweroff.target" }

      context "when systemd is installed" do
        before do
          allow(PackageSystem).to receive(:Installed).with("systemd") { true }
        end

        context "on a non s390 architecture" do
          before do
            allow(Arch).to receive(:s390) { false }
          end

          context "when ctrl+alt+del file not exist" do
            it "sets settings for shutdown as 'reboot'" do
              allow(FileUtils).to receive(:Exists).with(ctrl_alt_del_file) { false }

              Security.ReadConsoleShutdown              
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eql("reboot")
            end
          end

          context "when ctrl+del+alt file exist" do
            before do
              allow(FileUtils).to receive(:Exists).with(ctrl_alt_del_file) { true }
            end

            it "sets settings for shutdown as 'ignore' by default" do
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return("dummy_file")

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eql("ignore")
            end

            it "sets settings for shutdown as 'halt' if links to poweroff.target" do
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return(target_link)

              Security.ReadConsoleShutdown              
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eql("halt")
            end

            it "sets settings for shutdown as 'reboot' if links to reboot.target" do
              target_link = "/usr/lib/systemd/system/reboot.target"
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return(target_link)

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eql("reboot")
            end

            it "sets settings for shutdown as 'reboot' if links to ctrl-alt-del.target" do
              target_link = "/usr/lib/systemd/system/ctrl-alt-del.target"
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return(target_link)

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eql("reboot")
            end

          end
        end

        context "on a s390 architecture" do
          before do
            allow(Arch).to receive(:s390) { true }
          end

          context "when ctrl+alt+del file not exist" do
            it "sets settings for shutdown as 'reboot'" do
              allow(FileUtils).to receive(:Exists).with(ctrl_alt_del_file) { false }

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eql("halt")
            end
          end

          context "when ctrl+del+alt file exist" do
            before do
              allow(FileUtils).to receive(:Exists).with(ctrl_alt_del_file) { true }
            end

            it "sets settings for shutdown as 'ignore' by default" do
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return("dummy_file")

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eql("ignore")
            end

            it "sets settings for shutdown as 'halt' if links to poweroff.target" do
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return(target_link)

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eql("halt")
            end

            it "sets settings for shutdown as 'reboot' if links to reboot.target" do
              target_link = "/usr/lib/systemd/system/reboot.target"
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return(target_link)

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eql("reboot")
            end

            it "sets settings for shutdown as 'halt' if links to ctrl-alt-del.target" do
              target_link = "/usr/lib/systemd/system/ctrl-alt-del.target"
              allow(SCR).to receive(:Read).with(path(".target.symlink"), ctrl_alt_del_file)
                .and_return(target_link)

              Security.ReadConsoleShutdown
              expect(Security.Settings["CONSOLE_SHUTDOWN"]).to eql("halt")
            end

          end
        end
      end

      context "when systemd is not installed but inittab exist" do
        before do
          allow(PackageSystem).to receive(:Installed).with("systemd") { false }
        end

        context "on a non s390 architecture" do
          before do
            allow(Arch).to receive(:s390) { false }
            allow(::Security::CtrlAltDelConfig).to receive(:inittab?) { true }
          end

          context "when no inittab ca entry" do
            it "sets settings for shutdown as 'reboot'" do
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

    describe "#read_pam_settings" do
      before do
        change_scr_root(File.join(DATA_PATH, "system"))
      end

      after do
        reset_scr_root
      end

      it "sets passwd encryption setting based on /etc/login.defs" do
        allow(Pam).to receive(:Query)

        expect(Security.Settings["PASSWD_ENCRYPTION"]).to eql("sha512")
        Security.read_pam_settings
      end

      it "sets cracklib settings" do
        allow(Pam).to receive(:Query).with("pwhistory")
        allow(Pam).to receive(:Query).with("cracklib")
          .and_return("password" => ["dictpath=/shared/cracklib_dict", "minlen="])

        Security.read_pam_settings
        expect(Security.Settings["PASSWD_USE_CRACKLIB"]).to eql("yes")
        expect(Security.Settings["CRACKLIB_DICT_PATH"]).to eql("/shared/cracklib_dict")
        expect(Security.Settings["PASS_MIN_LEN"]).to eql("5")
      end

      it "sets password remember history settings" do
        allow(Pam).to receive(:Query).with("cracklib")
        allow(Pam).to receive(:Query).with("pwhistory")
          .and_return("password" => ["remember=5"])

        Security.read_pam_settings
        expect(Security.Settings["PASSWD_REMEMBER_HISTORY"]).to eql("5")
      end
    end

    describe "#read_permissions" do

      context "depending on current permission" do
        it "sets security permission to 'easy' if contains easy" do
          Security.Settings["PERMISSION_SECURITY"] = "easy local"

          expect(Security.read_permissions).to eql("easy")
          expect(Security.Settings["PERMISSION_SECURITY"]).to eql("easy")
        end

        it "sets user defined security permission" do
          Security.Settings["PERMISSION_SECURITY"] = "local user_defined "

          expect(Security.read_permissions).to eql("user_defined")
          expect(Security.Settings["PERMISSION_SECURITY"]).to eql("user_defined")
        end

        it "removes local permission" do
          Security.Settings["PERMISSION_SECURITY"] = "paranoid local"

          expect(Security.read_permissions).to eql("paranoid")
          expect(Security.Settings["PERMISSION_SECURITY"]).to eql("paranoid")
        end

        it "sets secure by default" do
          Security.Settings["PERMISSION_SECURITY"] = nil

          expect(Security.read_permissions).to eql("secure")
          expect(Security.Settings["PERMISSION_SECURITY"]).to eql("secure")
        end
      end

    end

    describe "#read_polkit_settings" do
      let(:polkit) do
        path(".etc.polkit-default-privs_local") + "org.freedesktop.upower.hibernate"
      end

      context "depending on current polkit config" do

        it "sets correctly hibernate system settings to 'anyone'" do
          allow(SCR).to receive(:Read).with(polkit) { "yes:yes:yes" }

          Security.read_polkit_settings
          expect(Security.Settings["HIBERNATE_SYSTEM"]).to eql("anyone")
        end

        it "sets correctly hibernate settings to 'auth_admin'" do
          allow(SCR).to receive(:Read).with(polkit) { "auth_admin:auth_admin:auth_admin" }

          Security.read_polkit_settings
          expect(Security.Settings["HIBERNATE_SYSTEM"]).to eql("auth_admin")
        end
        it "sets correctly hibernate settings to 'active_console' as default" do
          allow(SCR).to receive(:Read).with(polkit) { "any_other_entry" }

          Security.read_polkit_settings
          expect(Security.Settings["HIBERNATE_SYSTEM"]).to eql("active_console")
        end
      end

    end

    describe "#read_kernel_settings" do
      before do
        change_scr_root(File.join(DATA_PATH, "system"))
        Security.Settings["kernel.sysrq"]                 = nil
        Security.Settings["net.ipv4.tcp_syncookies"]      = nil
        Security.Settings["net.ipv4.ip_forward"]          = nil
        Security.Settings["net.ipv6.conf.all.forwarding"] = nil

        Security.read_kernel_settings
      end

      after do
        reset_scr_root
      end

      it "sets kernel settings based on /etc/sysctl.conf" do
        expect(Security.Settings["kernel.sysrq"]).to eql("0")
        expect(Security.Settings["net.ipv4.tcp_syncookies"]).to eql(true)
        expect(Security.Settings["net.ipv4.ip_forward"]).to eql(false)
        expect(Security.Settings["net.ipv6.conf.all.forwarding"]).to eql(false)
      end
    end

    describe "#read_from_locations" do
      after do
        reset_scr_root
      end

      before do
        change_scr_root(File.join(DATA_PATH, "system"))
        allow(SCR).to receive(:Read)
          .with(path(".sysconfig.displaymanager.DISPLAYMANAGER"))
          .and_return(display_manager)
      end

      context "when display manager is gdm" do
        let(:display_manager) { "gdm" }

        before do
          Security.init_settings
        end

        it "allows everybody to shutdown by default" do
          expect(Security.Settings["DISPLAYMANAGER_SHUTDOWN"]).to eql("all")
        end

        it "sets login definitions based on /etc/login.defs" do
          Security.read_from_locations
          expect(Security.Settings["FAIL_DELAY"]).to eql("3")
        end

        it "sets different settings based on /etc/sysconfig/*" do
          Security.read_from_locations
          expect(Security.Settings["DISPLAYMANAGER_REMOTE_ACCESS"]).to eql("yes")
          expect(Security.Settings["DISPLAYMANAGER_ROOT_LOGIN_REMOTE"]).to eql("yes")
          expect(Security.Settings["DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN"]).to eql("no")
          expect(Security.Settings["DISPLAYMANAGER_SHUTDOWN"]).to eql("all")
          expect(Security.Settings["PERMISSION_SECURITY"]).to eql("easy local")
          expect(Security.Settings["DISABLE_RESTART_ON_UPDATE"]).to eql("no")
        end
      end

      context "when display manager is kdm" do
        let(:display_manager) { "kdm" }

        before do
          allow(SCR).to receive(:Read).with(path(".kde4.kdmrc.AllowShutdown"))
            .and_return("All")
          Security.init_settings
          Security.read_from_locations
        end

        it "sets login definitions based on /etc/login.defs" do
          expect(Security.Settings["FAIL_DELAY"]).to eql("3")
        end

        it "sets login definitions based on /etc/login.defs" do
          expect(Security.Settings["FAIL_DELAY"]).to eql("3")
        end

        it "sets kde4 allow shutdown based on kdmrc" do
          expect(Security.Settings["AllowShutdown"]).to eql("All")
        end

        it "sets different settings based on /etc/sysconfig/*" do
          expect(Security.Settings["DISPLAYMANAGER_REMOTE_ACCESS"]).to eql("yes")
          expect(Security.Settings["DISPLAYMANAGER_ROOT_LOGIN_REMOTE"]).to eql("yes")
          expect(Security.Settings["DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN"]).to eql("no")
          expect(Security.Settings["PERMISSION_SECURITY"]).to eql("easy local")
          expect(Security.Settings["DISABLE_RESTART_ON_UPDATE"]).to eql("no")
        end
      end
    end

    describe "#read_shadow_config" do
      before do
        allow(shadow_config).to receive(:fail_delay).and_return("10")
      end

      it "reads login.defs configuration" do
        Security.read_shadow_config
        expect(Security.Settings["FAIL_DELAY"]).to eq("10")
      end
    end

    describe "#Read" do
      it "reads settings and returns true" do
        expect(Security).to receive(:read_from_locations)
        expect(Security).to receive(:ReadConsoleShutdown)
        expect(Security).to receive(:ReadServiceSettings)
        expect(Security).to receive(:read_pam_settings)
        expect(Security).to receive(:read_permissions)
        expect(Security).to receive(:read_polkit_settings)

        expect(Security.Read).to eql(true)
      end
    end

    describe "#Import" do
      before do
        # GENERAL
        Security.Settings["FAIL_DELAY"]       = "5"
        Security.Settings["PASS_MIN_LEN"]       = "3"
        Security.Settings["MANDATORY_SERVICES"] = "no"

        # SYSCTL
        Security.Settings["net.ipv4.ip_forward"] = true

        # OBSOLETE LOGIN DEFS
        Security.Settings["SYS_UID_MIN"] = 200
        Security.Settings["SYS_GID_MIN"] = 200

      end

      it "doest not touch current Settings if given settings are empty" do
        current = Security.Settings.dup
        expect(Security.Import({})).to eql(true)
        expect(Security.Settings).to eql(current)
      end

      context "when Settings keys exists in given settings" do
        it "imports given settings without modify" do
          expect(Security.Import("PASS_MIN_LEN" => "8", "MANDATORY_SERVICES" => "yes")).to eql(true)
          expect(Security.Settings["PASS_MIN_LEN"]).to eql("8")
          expect(Security.Settings["MANDATORY_SERVICES"]).to eql("yes")
        end
      end

      context "when Settings keys do not exist in given settings" do
        it "imports SYSCTL settings modifying key names and adapting values" do
          expect(Security.Import("IP_FORWARD" => "no")).to eql(true)

          expect(Security.Settings["net.ipv4.ip_forward"]).to eql(false)
        end

        it "imports LOGIN DEFS settings transforming key name" do
          expect(Security.Import("SYSTEM_UID_MIN" => "150")).to eql(true)
          expect(Security.Import("SYSTEM_GID_MIN" => "150")).to eql(true)

          expect(Security.Settings["SYS_UID_MIN"]).to eql("150")
          expect(Security.Settings["SYS_GID_MIN"]).to eql("150")
        end

        it "imports enable_sysrq settings transforming key name" do
          expect(Security.Import("enable_sysrq" => "no")).to eql(true)

          expect(Security.Settings["kernel.sysrq"]).to eql("0")
        end

        it "does not modify not given settings" do
          expect(Security.Import("EXTRA_SERVICES" => "yes")).to eql(true)

          expect(Security.Settings["FAIL_DELAY"]).to eql("5")
        end

      end

    end
  end
end
