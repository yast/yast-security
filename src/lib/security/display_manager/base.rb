module Security
  module DisplayManager
    class Base
      attr_accessor :name

      def initialize(name)
        @name = (name)
      end

      def default_settings
        { shutdown_key => "all" }
      end

      def shutdown_key
        "DISPLAY_MANAGER"
      end

      def default_locations
        {
          ".sysconfig.displaymanager" => [
            "DISPLAYMANAGER_REMOTE_ACCESS",
            "DISPLAYMANAGER_ROOT_LOGIN_REMOTE",
            "DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN",
            shutdown_key
          ]
        }
      end
    end
  end
end

