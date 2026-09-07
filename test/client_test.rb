require "minitest/autorun"
require "radical_id_client"

class ClientTest < Minitest::Test
  def client(status: 200, data: profile, &block)
    RadicalIdClient::Client.new(origin: "https://id.example", token: "secret", transport: block || ->(*) { [ status, JSON.generate(data) ] })
  end

  def profile
    { issuer: "https://id.example", sub: "abc", name: "Test", email: "a@example.com", email_verified: true, eligible: true }
  end

  def test_lookup_normalizes_email_and_keeps_credentials_out_of_url
    c = client do |method, uri, headers, body|
      assert_equal :post, method
      assert_equal "/api/v1/users/lookup", uri.path
      assert_nil uri.query
      assert_equal "Bearer secret", headers["Authorization"]
      assert_equal "admin", headers["X-Actor-Subject"]
      assert_equal "a@example.com", JSON.parse(body)["email"]
      [ 200, JSON.generate(profile) ]
    end
    assert_equal "abc", c.lookup_user(email: " A@example.com ", actor_sub: "admin").sub
  end

  def test_rejects_untrusted_origins
    [ "http://id.example", "https://user:pass@id.example", "https://id.example/path", "https://id.example?token=a" ].each do |origin|
      assert_raises(RadicalIdClient::ConfigurationError) { RadicalIdClient::Client.new(origin: origin, token: "a") }
    end
  end

  def test_rejects_bad_subject_before_transport
    assert_raises(ArgumentError) { client.fetch_user(sub: "../other", actor_sub: "admin") }
  end

  def test_typed_errors_and_no_redirects
    { 401 => RadicalIdClient::Unauthorized, 403 => RadicalIdClient::Forbidden, 404 => RadicalIdClient::NotFound,
     422 => RadicalIdClient::Ineligible, 429 => RadicalIdClient::RateLimited, 302 => RadicalIdClient::InvalidResponse }.each do |status, error|
      assert_raises(error) { client(status: status).lookup_user(email: "a@b.com", actor_sub: "admin") }
    end
  end

  def test_checks_issuer_and_required_claims
    assert_raises(RadicalIdClient::InvalidResponse) { client(data: profile.merge(issuer: "https://evil.example")).fetch_user(sub: "abc", actor_sub: "admin") }
    assert_raises(RadicalIdClient::InvalidResponse) { client(data: {}).fetch_user(sub: "abc", actor_sub: "admin") }
  end

  def test_network_retries_are_bounded
    count = 0
    c = client { |*| count += 1; raise Timeout::Error }
    assert_raises(RadicalIdClient::Unavailable) { c.ensure_application_access(sub: "abc", actor_sub: "admin") }
    assert_equal 2, count
  end

  def test_rejects_wrong_subject_and_oversized_or_malformed_responses
    assert_raises(RadicalIdClient::InvalidResponse) { client.fetch_user(sub: "different", actor_sub: "admin") }
    [ "not json", "x" * 65_537 ].each do |body|
      c = client { |*| [ 200, body ] }
      assert_raises(RadicalIdClient::InvalidResponse) { c.lookup_user(email: "a@example.com", actor_sub: "admin") }
    end
  end

  def test_profiles_are_immutable
    result = client.fetch_user(sub: "abc", actor_sub: "admin")
    assert result.frozen?
    assert result.email.frozen?
  end
end
