# Helpers for stubbing several agent operations.
#
# Must be included in the configure section of RSpec.
#
# @example usage
#     RSpec.configure do |c|
#       c.include SCRStub
#     end
#
#     describe "Keyboard" do
#       it "uses loadkeys" do
#         expect_to_execute(/loadkeys/)
#         Keyboard.Set
#       end
#     end
#
module SCRStub
  # Ensures that non-stubbed SCR calls still works as expected after including
  # the module in the testsuite
  # different methods of the module
  def self.included(testsuite)
    testsuite.before(:each) do
      allow(Yast::SCR).to receive(:Read).and_call_original
      allow(Yast::SCR).to receive(:Write).and_call_original
      allow(Yast::SCR).to receive(:Execute).and_call_original
    end
  end

  # Matcher for executing commands using SCR.Execute and .target.bash
  #
  # @return [RSpec::Mocks::Matchers::Receive]
  def exec_bash(command)
    receive(:Execute).with(path(".target.bash"), command)
  end

  # Matcher for executing commands using SCR.Execute and .target.bash_output
  #
  # @return [RSpec::Mocks::Matchers::Receive]
  def exec_bash_output(command)
    receive(:Execute).with(path(".target.bash_output"), command)
  end

  # Stub all calls to SCR.Write storing the value for future comparison
  def stub_scr_write
    @written_values = {}
    allow(Yast::SCR).to receive(:Write) do |*args|
      key = args[0].to_s.gsub(/[\"']/, "")
      @written_values[key] = args[1]
    end
  end

  # Value written by a stubbed call to SCR.Write
  #
  # @param key used in the call to SCR.Write
  def written_value_for(key)
    @written_values[key]
  end

  # Checks if SCR.Write was called for a given path
  #
  # @param path used in the call to SCR.Write
  def was_written?(path)
    @written_values.has_key?(path)
  end

  # Substitute for the same method found in Yast::RSpec::SCR in yast2 >= 3.1.26
  # Block support not implemented because it's not used in this test suite
  def change_scr_root(directory)
    if @scr_handle
      raise "There is already an open chrooted SCR instance, "\
        "a call to reset_scr_root was expected"
    end

    if !File.directory?(directory)
      raise "#{directory} is not a valid directory"
    end

    @scr_original_handle = Yast::WFM.SCRGetDefault
    check_version = false
    @scr_handle = Yast::WFM.SCROpen("chroot=#{directory}:scr", check_version)
    if @scr_handle < 0
      @scr_handle = nil
      @scr_original_handle = nil
      raise "Error creating the chrooted SCR instance"
    end
    Yast::WFM.SCRSetDefault(@scr_handle)
  end

  # Substitute for the same method found in Yast::RSpec::SCR in
  # yast2-ruby-bindings >= 3.1.26
  def reset_scr_root
    if @scr_handle.nil?
      raise "Unable to find a chrooted SCR instance to close"
    end

    default_handle = Yast::WFM.SCRGetDefault
    if default_handle != @scr_handle
      raise "Error closing the chrooted SCR instance, "\
        "it's not the current default one"
    end

    Yast::WFM.SCRClose(default_handle)
    Yast::WFM.SCRSetDefault(@scr_original_handle)
  ensure
    @scr_handle = nil
    @scr_original_handle = nil
  end

  # Equivalent for the same method found in Yast::RSpec::Shorcuts in
  # yast2-ruby-bindings >= 3.1.26
  def path(route)
    Yast::Path.new(route)
  end
end
