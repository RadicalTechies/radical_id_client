module RadicalIdClient
  module Rails
    # The host owns identity mapping, role policy and membership assignment.
    class Adapter
      attr_reader :session_model

      def initialize(session_model: false)
        @session_model = session_model
      end

      def active?(user)
        user && (!user.respond_to?(:disabled?) || !user.disabled?) &&
          (!user.respond_to?(:active?) || user.active?)
      end

      def administrator?(user)
        active?(user) && user.admin? && (!user.respond_to?(:read_only?) || !user.read_only?)
      end

      def signed_in_user(request)
        if session_model
          row = session_class.usable.find_by(id: request.cookie_jar.signed[:session_id])
          row&.user if row && active?(row.user)
        elsif request.session[:authenticated_at].to_i >= 12.hours.ago.to_i
          user = ::User.find_by(id: request.session[:user_id])
          user if active?(user)
        end
      end

      def deadline(request)
        if session_model
          source_session!(request).created_at + session_class::MAX_LIFETIME
        else
          Time.at(request.session[:authenticated_at].to_i) + 12.hours
        end
      end

      def source_valid?(record)
        return true unless session_model
        ::Session.usable.exists?(id: record.source_session_id, user_id: record.actor_id)
      end

      def subject(user)
        key = %i[uuid uid oidc_subject oidc_sub].find { |name| user.respond_to?(name) && !user.public_send(name).to_s.empty? }
        raise ConfigurationError, "The host adapter must supply an administrator subject" unless key
        user.public_send(key).to_s.split("|").last
      end

      def identity_attributes(profile, kind:)
        raise ConfigurationError, "The host adapter must implement identity_attributes"
      end

      def model_for(kind)
        return ::User if kind == "User"
        return ::Customer if kind == "Customer" && customers?
        raise Ineligible, "Invalid account type"
      end

      def portal_inboxes = []

      def client
        Client.new(origin: ENV["RADICAL_ID_API_ORIGIN"].presence || ENV["OIDC_ISSUER"], token: ENV["RADICAL_ID_API_TOKEN"])
      end

      def provisionable? = ENV["RADICAL_ID_API_TOKEN"].present?
      def customers? = false
      def landing_path(user, inbox: nil) = "/"
      def blocked_path?(path)
        protected_segments = %w[auth oauth saml oidc webauthn magic_link invitation welcome onboarding profile settings
          mcp good_job jobs users memberships branch_memberships api_tokens oauth_clients mcp_tokens
          application_api_credentials credentials identities google_accounts oauth_connections mcp_connections
          imap_accounts permissions system]
        (path.split("/") & protected_segments).any?
      end

      def logout_request?(request)
        request.delete? && request.path.match?(%r{/(session|sessions|sign_out|logout|sign-out)\z})
      end

      def session_class
        unless defined?(::Session) && ::Session.respond_to?(:usable) && ::Session.const_defined?(:MAX_LIFETIME)
          raise ConfigurationError, "Session adapters require Session.usable and Session::MAX_LIFETIME"
        end
        ::Session
      end

      def source_session!(request)
        session_class.usable.find_by(id: request.cookie_jar.signed[:session_id]) ||
          raise(Forbidden, "Your session has expired. Sign in again.")
      end

      def target_session_valid?(request, record)
        if session_model
          request.cookie_jar.signed[:session_id].to_s == record.target_session_id.to_s &&
            session_class.usable.exists?(id: record.target_session_id, user_id: record.target_id)
        elsif record.target_type == "Customer"
          request.session[:customer_id].to_s == record.target_id.to_s && request.session[:user_id].blank?
        else
          request.session[:user_id].to_s == record.target_id.to_s
        end
      end

      def start(request, target, inbox: nil)
        raise Forbidden, "Already impersonating" if request.session[:radical_id_impersonation_id]
        actor = signed_in_user(request)
        raise Forbidden, "Administrator access required" unless administrator?(actor)
        raise Ineligible, "Choose another active account" unless active?(target) && !(target.is_a?(::User) && target.id == actor.id)
        source = session_model ? source_session!(request) : nil
        record = Impersonation.transaction do
          # Hold the original login row until the temporary session and audit
          # record are durable. No browser identity is changed on a failed write.
          source&.lock!
          if source && !session_class.usable.exists?(id: source.id, user_id: actor.id)
            raise Forbidden, "Your session has expired. Sign in again."
          end
          raise Forbidden, "Administrator access required" unless administrator?(actor.reload)
          expires = source ? source.created_at + session_class::MAX_LIFETIME : deadline(request)
          raise Forbidden, "Your session has expired. Sign in again." unless expires > Time.current
          entry = Impersonation.create!(actor_id: actor.id, target_id: target.id, target_type: target.class.name,
            expires_at: [ 30.minutes.from_now, expires ].min, actor_expires_at: expires,
            source_session_id: source&.id, authenticated_at: request.session[:authenticated_at], started_at: Time.current)
          if source
            attrs = { user: target, user_agent: request.user_agent, ip_address: request.remote_ip, created_at: source.created_at }
            attrs[:authentication_method] = "impersonation" if session_class.column_names.include?("authentication_method")
            entry.update!(target_session_id: session_class.create!(attrs).id)
          end
          event!("impersonation.started", actor: actor, target: target, request: request, impersonation: entry)
          entry
        end
        request.reset_session
        request.session[:radical_id_impersonation_id] = record.id
        establish_target(request, target, record)
        record
      rescue ActiveRecord::RecordNotFound
        raise Forbidden, "Your session or the target account is no longer available."
      end

      def establish_target(request, target, record)
        if session_model
          request.cookie_jar.signed[:session_id] = { value: record.target_session_id, httponly: true, same_site: :lax, secure: request.ssl? }
        elsif record.target_type == "Customer"
          request.session[:customer_id] = target.id
          request.session[:customer_authenticated_at] = record.authenticated_at
        else
          request.session[:user_id] = target.id
        end
        request.session[:authenticated_at] = record.authenticated_at || record.started_at.to_i
      end

      def finish(request, record, reason:, restore: true)
        actor = record.actor
        can_restore = restore && administrator?(actor) && source_valid?(record) && record.actor_expires_at > Time.current
        record.update!(ended_at: Time.current, end_reason: reason) unless record.ended_at
        ::Session.where(id: record.target_session_id).delete_all if session_model
        request.reset_session
        request.cookie_jar.delete(:session_id) if session_model
        if can_restore
          if session_model
            request.cookie_jar.signed[:session_id] = { value: record.source_session_id, httponly: true, same_site: :lax, secure: request.ssl? }
          else
            request.session[:user_id] = actor.id
          end
          request.session[:authenticated_at] = record.authenticated_at
        elsif session_model && !restore
          ::Session.where(id: record.source_session_id).delete_all
        end
        event!("impersonation.ended", actor: actor, target: record.target, request: request, impersonation: record, details: { reason: reason })
        can_restore
      end

      def event!(action, actor:, target: nil, request:, impersonation: nil, details: {})
        AdminEvent.create!(action: action, actor_id: actor&.id, target_id: target&.id, target_type: target&.class&.name,
          impersonation_id: impersonation&.id, request_id: request.request_id, details: details)
      end

      def validate_profile!(profile, kind:)
        raise Ineligible, "The Radical ID user must be active and verified" unless profile.eligible && profile.email_verified
      end

      def identity_for(profile, kind:)
        model = model_for(kind)
        identity = identity_attributes(profile, kind: kind)
        user = model.find_by(identity)
        by_email = model.find_by(email: profile.email.strip.downcase)
        if by_email && by_email != user
          # Only an unbound provisional row may be adopted by verified email.
          bound = identity.keys.any? { |key| by_email.public_send(key).present? }
          raise Conflict, "This email belongs to a different identity. Resolve it before adding the user." if bound || user
          user = by_email
        end
        raise Ineligible, "This local account is disabled" if user && !active?(user)
        user || model.new
      end

      def provision!(profile, kind:)
        validate_profile!(profile, kind: kind)
        user = identity_for(profile, kind: kind)
        user.assign_attributes(identity_attributes(profile, kind: kind).merge(name: profile.name, email: profile.email.strip.downcase))
        prepare_user(user, profile)
        user.save!
        user
      end

      def prepare_user(user, profile); end
      def access_fields(kind) = []
      def validate_access!(params, kind:)
        raise Ineligible, "Invalid account type" unless kind == "User" || (customers? && kind == "Customer")
        fields = access_fields(kind)
        submitted = params[:access] || {}
        raise Ineligible, "Unknown access field" unless (submitted.keys.map(&:to_s) - fields.map { |field| field[:key].to_s }).empty?
        fields.each do |field|
          values = Array(submitted[field[:key].to_s]).reject(&:blank?).map(&:to_s)
          allowed = field[:options].map { |_, value| value.to_s }
          raise Ineligible, "Invalid access selection" unless (values - allowed).empty? && (field[:multiple] || values.size <= 1)
        end
      end
      def assign_access!(user, params, actor:); end
    end
  end
end
