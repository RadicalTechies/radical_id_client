module RadicalIdClient
  module Rails
    class AdminEvent < ActiveRecord::Base
      self.table_name = "radical_id_admin_events"
    end
  end
end
