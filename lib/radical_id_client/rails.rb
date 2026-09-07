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
      config.root = File.expand_path("../..", __dir__)
      isolate_namespace RadicalIdClient::Rails

      initializer "radical_id_client.audit_context" do
        ActiveSupport.on_load(:action_controller_base) do
          include RadicalIdClient::Rails::AuditHelpers
        end
        ActiveSupport.on_load(:active_job) do
          prepend RadicalIdClient::Rails::JobAudit
        end
      end
    end
  end
end
require "radical_id_client/rails/adapter"
require "radical_id_client/rails/session_guard"
require "radical_id_client/rails/audit_helpers"
