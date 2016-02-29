#!/usr/bin/env rspec

require_relative "test_helper"
require "security/ctrl_alt_del_config"

module Security

  describe CtrlAltDelConfig do

    def stub_arch(arch)
      Yast.import "Arch"

      allow(Yast::Arch).to receive(arch) { true }
    end

    describe ".default" do

      it "returns 'halt' for a s390 architecture" do
        stub_arch("s390")

        expect(subject.default).to eql("halt")
      end

      it "returns 'reboot' for non s390 architecture" do
        expect(subject.default).to eql("reboot")
      end
    end

    describe ".systemd?" do

      it "returns false if not systemd package installed" do
        allow(Yast::Package).to receive(:Installed).with("systemd") { false }

        expect(subject.systemd?).to eql(false)
      end

      it "returns true if systemd package installed" do
        allow(Yast::Package).to receive(:Installed).with("systemd") { true }

        expect(subject.systemd?).to eql(true)
      end

    end

    describe ".inittab?" do

      it "returns true if inittab file exist" do
        allow(File).to receive(:exist?).with("/etc/inittab") { true }

        expect(subject.inittab?).to eql(true)
      end

      it "returns false if not inittab file exist" do
        allow(File).to receive(:exist?).with("/etc/inittab") { false }

        expect(subject.inittab?).to eql(false)
      end
    end

    describe ".current" do

      it "returns nil if not systemd and not innitab config" do
        allow(subject).to receive(:systemd?) { false }
        allow(subject).to receive(:inittab?) { false }

        expect(subject.current).to eql(nil)
      end

    end

    describe ".current_systemd" do
      let(:target_link) { "/usr/lib/systemd/system/poweroff.target" }

      context "when no config file exists" do
        it "returns nil if not config tile exists" do
          allow(File).to receive(:exist?).with(subject::SYSTEMD_FILE) { false }

          expect(subject.current_systemd).to be_nil
        end
      end

      context "when config file exists" do
        before do
          allow(File).to receive(:exist?).with(subject::SYSTEMD_FILE) { true }
        end

        it "returns 'halt' if links to poweroff.target" do
          allow(Yast::SCR).to receive(:Read).with(path(".target.symlink"), subject::SYSTEMD_FILE)
            .and_return(target_link)

          expect(subject.current_systemd).to eql("halt")
        end

        it "returns 'reboot' if links to reboot.target" do
          target_link = "/usr/lib/systemd/system/reboot.target"
          allow(Yast::SCR).to receive(:Read).with(path(".target.symlink"), subject::SYSTEMD_FILE)
            .and_return(target_link)

          expect(subject.current_systemd).to eql("reboot")
        end

        it "returns default value if links to ctrl-alt-del.target" do
          target_link = "/usr/lib/systemd/system/ctrl-alt-del.target"
          allow(Yast::SCR).to receive(:Read).with(path(".target.symlink"), subject::SYSTEMD_FILE)
            .and_return(target_link)
          allow(subject).to receive(:default) { "reboot or shutdown" }

          expect(subject.current_systemd).to eql("reboot or shutdown")
        end

        it "returns 'ignore' if links to any other file" do
          allow(Yast::SCR).to receive(:Read).with(path(".target.symlink"), subject::SYSTEMD_FILE)
            .and_return("dummy_file")

          expect(subject.current_systemd).to eql("ignore")
        end

      end
    end

    describe ".current_inittab" do
      it "returns nil if not ca entry" do
        allow(Yast::SCR).to receive(:Read).with(path(".etc.inittab.ca")) { nil }
        #allow(Yast::SCR).to receive(:Read).with(path(".etc.inittab.ca")) { "12345:/bin/shutdown -h now" }

        expect(subject.current_inittab).to be_nil
      end

    end

  end

end
