module RadicalIdClient
  module Rails
    module AuditHelpers
      extend ActiveSupport::Concern
      included do
        helper_method :true_user, :impersonating?
      end

      def impersonating? = Context.audit.present?
      def true_user
        Context.audit ? ::User.find_by(id: Context.audit["actor_id"]) : Rails.adapter.signed_in_user(request)
      end
    end

    module JobAudit
      def serialize
        super.merge("radical_id_audit" => Context.audit || @radical_id_audit)
      end

      def deserialize(data)
        super
        @radical_id_audit = data["radical_id_audit"]
      end

      def perform_now
        return super unless @radical_id_audit
        Context.set(audit: @radical_id_audit) do
          AdminEvent.create!(action: "impersonation.job", **@radical_id_audit.symbolize_keys,
            details: { job_class: self.class.name, job_id: job_id })
          super
        end
      end
    end
  end
end
