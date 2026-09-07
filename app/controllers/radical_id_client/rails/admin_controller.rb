module RadicalIdClient
  module Rails
    class AdminController < ActionController::Base
      protect_from_forgery with: :exception
      layout "radical_id_client/rails/admin"
      before_action :authorize_admin
      rescue_from RadicalIdClient::Error, with: :identity_error
      rescue_from ActiveRecord::RecordInvalid, ActiveRecord::RecordNotUnique, with: :persistence_error

      def index
        @kind = params[:kind] == "Customer" && adapter.customers? ? "Customer" : "User"
        @users = adapter.model_for(@kind).order(:email)
        if params[:q].present?
          @users = @users.where("email ILIKE ?", "%#{ActiveRecord::Base.sanitize_sql_like(params[:q].to_s)}%")
        end
        @users = @users.limit(100)
      end

      def lookup
        raise ConfigurationError, "Radical ID provisioning is not configured" unless adapter.provisionable?
        @kind = params[:kind].to_s
        adapter.validate_access!({}, kind: @kind)
        @profile = adapter.client.lookup_user(email: params[:email], actor_sub: adapter.subject(@actor), request_id: request.request_id)
        raise Ineligible, "This Radical ID account is not active and verified" unless @profile.eligible && @profile.email_verified
        @review = verifier.generate({ sub: @profile.sub, kind: @kind, actor_id: @actor.id }, purpose: :provision, expires_in: 10.minutes)
        response.headers["Cache-Control"] = "no-store"
        adapter.event!("user.lookup", actor: @actor, request: request)
        render :review
      end

      def provision
        data = verifier.verified(params[:review], purpose: :provision)&.with_indifferent_access
        raise Ineligible, "The profile review expired. Look up the email again." unless data && data[:actor_id] == @actor.id
        adapter.validate_access!(params, kind: data[:kind])
        profile = adapter.client.fetch_user(sub: data[:sub], actor_sub: adapter.subject(@actor), request_id: request.request_id)
        adapter.validate_profile!(profile, kind: data[:kind])
        # Detect local conflicts before making a remote grant. Recheck inside
        # the transaction as the remote call cannot share our database lock.
        adapter.identity_for(profile, kind: data[:kind])
        profile = adapter.client.ensure_application_access(sub: profile.sub, actor_sub: adapter.subject(@actor), request_id: request.request_id)
        @central_granted = true
        user = adapter.model_for(data[:kind]).transaction do
          result = adapter.provision!(profile, kind: data[:kind])
          adapter.assign_access!(result, params, actor: @actor)
          adapter.event!("user.provisioned", actor: @actor, target: result, request: request)
          result
        end
        redirect_to "/identity_admin?kind=#{data[:kind]}", notice: "#{user.email} is available in this application."
      end

      def impersonate
        kind = params[:kind].to_s
        adapter.validate_access!({}, kind: kind)
        target = adapter.model_for(kind).find(params[:user_id])
        destination = adapter.landing_path(target, inbox: params[:inbox_id])
        adapter.start(request, target)
        redirect_to destination, status: :see_other
      end

      def stop
        adapter.finish(request, @impersonation, reason: "returned") if @impersonation
        redirect_to "/identity_admin", status: :see_other
      end

      private

      def adapter = Rails.adapter
      def verifier = ::Rails.application.message_verifier("radical-id-profile-review")

      def authorize_admin
        response.headers["Cache-Control"] = "no-store"
        @impersonation = Impersonation.find_by(id: session[:radical_id_impersonation_id])
        if @impersonation
          return head :forbidden unless @impersonation.live? && adapter.administrator?(@impersonation.actor)
          return head :forbidden unless %w[index stop].include?(action_name)
          @actor = @impersonation.actor
        else
          @actor = adapter.signed_in_user(request)
          head :forbidden unless adapter.administrator?(@actor)
        end
      end

      def identity_error(error)
        message = case error
        when NotFound then "No Radical ID account was found. Ask a Radical ID administrator to invite them first."
        when Unauthorized, Forbidden then "The Radical ID credential does not permit this operation. Contact an administrator."
        when Unavailable then "Radical ID is unavailable. Try again shortly."
        when RateLimited then "Too many lookups. Wait a minute and try again."
        else error.message
        end
        message = "Radical ID access was granted, but local setup failed. Retry this lookup to finish setup." if @central_granted
        redirect_to "/identity_admin", alert: message
      end

      def persistence_error(_error)
        identity_error(Error.new("The user could not be saved. Check the selected access and identity conflicts."))
      end
    end
  end
end
