module RadicalIdClient
  module Rails
    # Installed after Rails sessions but before OmniAuth. Middleware coverage
    # includes mounted engines and auth request phases outside host controllers.
    class SessionGuard
      def initialize(app) = @app = app

      def call(env)
        request = ActionDispatch::Request.new(env)
        id = request.session[:radical_id_impersonation_id]
        adapter = Rails.adapter
        # A signed application Session cookie must never become an ordinary
        # login if its accompanying Rails cookie is dropped or expires.
        record = Impersonation.find_by(id: id) if id
        if !id && adapter.session_model && request.cookie_jar.signed[:session_id]
          record = Impersonation.find_by(target_session_id: request.cookie_jar.signed[:session_id])
          request.session[:radical_id_impersonation_id] = record.id if record
        end
        return @app.call(env) unless id || record
        unless record
          request.reset_session
          request.cookie_jar.delete(:session_id) if adapter.session_model
          return redirect("/")
        end
        unless record.live? && adapter.administrator?(record.actor) && adapter.active?(record.target) && adapter.source_valid?(record)
          restored = adapter.finish(request, record, reason: "expired_or_revoked")
          return redirect(restored ? "/identity_admin" : "/")
        end
        # Stop is deliberately reachable without the target's admin permissions.
        if request.path != "/identity_admin/stop" && !adapter.logout_request?(request) && adapter.blocked_path?(Rack::Utils.unescape_path(request.path))
          return [ 403, { "content-type" => "text/html; charset=utf-8", "cache-control" => "no-store" },
            [ '<p>This action is unavailable while impersonating.</p><a href="/identity_admin">Return to admin controls</a>' ] ]
        end
        Context.set(audit: { "actor_id" => record.actor_id, "target_id" => record.target_id,
          "target_type" => record.target_type, "impersonation_id" => record.id }) do
          response = @app.call(env)
          if adapter.logout_request?(request) && response[0] < 400
            adapter.finish(request, record, reason: "logout", restore: false)
          end
          adapter.event!("impersonation.request", actor: record.actor, target: record.target, request: request,
            impersonation: record, details: { method: request.request_method, controller: request.path_parameters[:controller], action: request.path_parameters[:action], status: response[0] })
          response
        end
      end

      private

      def redirect(path) = [ 303, { "location" => path, "content-type" => "text/html", "cache-control" => "no-store" }, [] ]
    end
  end
end
