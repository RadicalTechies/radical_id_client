require "radical_id_client"
require "rails/engine"
require "active_record"
require "action_controller/railtie"

module RadicalIdClient
  module Rails
    class << self
      attr_accessor :adapter
    end

    class Engine < ::Rails::Engine
      isolate_namespace RadicalIdClient::Rails
    end
  end
end
require "radical_id_client/rails/adapter"
require "radical_id_client/rails/session_guard"
