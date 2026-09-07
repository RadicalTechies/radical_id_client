require "minitest/autorun"
require "radical_id_client"
require "radical_id_client/rails/adapter"

class AdapterTest < Minitest::Test
  def test_host_contract_failures_are_explicit
    adapter = RadicalIdClient::Rails::Adapter.new
    assert_raises(RadicalIdClient::ConfigurationError) { adapter.subject(Object.new) }
    assert_raises(RadicalIdClient::ConfigurationError) { adapter.identity_attributes(nil, kind: "User") }
    assert_empty adapter.portal_inboxes
  end

  def test_subject_uses_first_present_supported_identity
    user = Struct.new(:uid, :oidc_sub).new(nil, "openid_connect|subject-1")
    assert_equal "subject-1", RadicalIdClient::Rails::Adapter.new.subject(user)
  end

  def test_provisioning_normalizes_email_before_persistence
    record = Struct.new(:attributes) do
      def assign_attributes(value) = self.attributes = value
      def save! = true
    end.new
    adapter = RadicalIdClient::Rails::Adapter.new
    adapter.define_singleton_method(:identity_for) { |*, **| record }
    adapter.define_singleton_method(:identity_attributes) { |*, **| { uid: "sub" } }
    profile = RadicalIdClient::Profile.new(issuer: "https://id.example", sub: "sub", name: "Person",
      email: " Person@Example.com ", email_verified: true, eligible: true, branch: nil, branch_slug: nil)
    adapter.provision!(profile, kind: "User")
    assert_equal "person@example.com", record.attributes[:email]
  end
end
