module RadicalIdClient
  module Rails
    class Impersonation < ActiveRecord::Base
      self.table_name = "radical_id_impersonations"
      def actor = ::User.find_by(id: actor_id)
      def target = (target_type == "Customer" ? ::Customer : ::User).find_by(id: target_id)
      def live? = ended_at.nil? && expires_at > Time.current
    end
  end
end
