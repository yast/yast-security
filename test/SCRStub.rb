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

  # Shortcut for generating Yast::Path objects
  #
  # @param route [String] textual representation of the path
  # @return [Yast::Path] the corresponding Path object
  def path(route)
    Yast::Path.new(route)
  end

  # Encapsulates subsequent SCR calls into a chroot.
  #
  # Raises an exception if something goes wrong.
  #
  # @param [#to_s] directory to use as '/' for SCR calls
  def set_root_path(directory)
    check_version = false
    @scr_handle = Yast::WFM.SCROpen("chroot=#{directory}:scr", check_version)
    raise "Error creating the chrooted scr instance" if @scr_handle < 0
    Yast::WFM.SCRSetDefault(@scr_handle)
  end

  # Resets the SCR calls to default behaviour, closing the SCR instance open by
  # #set_root_path.
  #
  # Raises an exception if #set_root_path has not been called before (or if the
  # corresponding instance has already been closed)
  #
  # @see #set_root_path
  def reset_root_path
    default_handle = Yast::WFM.SCRGetDefault
    if default_handle != @scr_handle
      raise "Error closing the chrooted scr instance, it's not the current default one"
    end
    @scr_handle = nil
    Yast::WFM.SCRClose(default_handle)
  end

  # Matcher for executing commands using SCR.Execute and .target.bash
  #
  # @return [RSpec::Mocks::Matchers::Receive]
  def exec_bash(command)
    receive(:Execute).with(path(".target.bash"), command)
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
end
