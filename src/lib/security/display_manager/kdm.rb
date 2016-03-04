require 'security/display_manager/base'

module Security
  module DisplayManager
    class KDM < Base

      def shutdown_key
        "AllowShutdown"
      end

      def default_locations
        {
          ".kde4.kdmrc"               => shutdown_key,
          ".sysconfig.displaymanager" => [
            "DISPLAYMANAGER_REMOTE_ACCESS",
            "DISPLAYMANAGER_ROOT_LOGIN_REMOTE",
            "DISPLAYMANAGER_XSERVER_TCP_PORT_6000_OPEN"
          ]
        }
      end
    end
  end
end
