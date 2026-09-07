require "json"
require "net/http"
require "uri"
require "securerandom"

module RadicalIdClient
  class Error < StandardError; end
  class ConfigurationError < Error; end
  class Unauthorized < Error; end
  class Forbidden < Error; end
  class NotFound < Error; end
  class Conflict < Error; end
  class Ineligible < Error; end
  class RateLimited < Error; end
  class Unavailable < Error; end
  class InvalidResponse < Error; end

  Profile = Data.define(:issuer, :sub, :name, :email, :email_verified, :eligible, :branch, :branch_slug)

  class Client
    MAX_RESPONSE_BYTES = 65_536
    ERRORS = { 401 => Unauthorized, 403 => Forbidden, 404 => NotFound,
      409 => Conflict, 422 => Ineligible, 429 => RateLimited }.freeze

    def initialize(origin:, token:, transport: nil, allow_http: false)
      @origin = URI.parse(origin.to_s)
      unless @origin.is_a?(URI::HTTP) && @origin.host &&
          (@origin.scheme == "https" || (allow_http && %w[localhost 127.0.0.1 ::1].include?(@origin.hostname))) &&
          !@origin.userinfo && !@origin.query && !@origin.fragment && [ "", "/" ].include?(@origin.path)
        raise ConfigurationError, "Radical ID needs a fixed HTTPS origin"
      end
      raise ConfigurationError, "Radical ID service credential is missing" if token.to_s.empty?
      @token = token
      @transport = transport || method(:transmit)
    rescue URI::InvalidURIError
      raise ConfigurationError, "Invalid Radical ID origin"
    end

    def lookup_user(email:, actor_sub:, request_id: SecureRandom.uuid)
      profile(request(:post, "/api/v1/users/lookup", { email: email.to_s.strip.downcase }, actor_sub, request_id))
    end

    def fetch_user(sub:, actor_sub:, request_id: SecureRandom.uuid)
      checked_subject(profile(request(:get, "/api/v1/users/#{subject_path(sub)}", nil, actor_sub, request_id)), sub)
    end

    def ensure_application_access(sub:, actor_sub:, request_id: SecureRandom.uuid)
      checked_subject(profile(request(:put, "/api/v1/application/users/#{subject_path(sub)}", {}, actor_sub, request_id)), sub)
    end

    private

    def checked_subject(result, sub)
      raise InvalidResponse, "Radical ID returned a different subject" unless result.sub == sub
      result
    end

    def subject_path(sub)
      raise ArgumentError, "Invalid subject" unless sub.to_s.match?(/\A[a-zA-Z0-9_-]{1,128}\z/)
      sub
    end

    def request(method, path, body, actor_sub, request_id)
      headers = { "Authorization" => "Bearer #{@token}", "Content-Type" => "application/json",
        "Accept" => "application/json", "X-Actor-Subject" => actor_sub.to_s, "X-Request-ID" => request_id.to_s }
      attempts = 0
      begin
        status, text = @transport.call(method, @origin + path, headers, body && JSON.generate(body))
        raise (ERRORS[status] || (status >= 500 ? Unavailable : InvalidResponse)), "Radical ID request failed (#{status})" unless status == 200
        raise InvalidResponse, "Radical ID response is too large" if text.bytesize > MAX_RESPONSE_BYTES
        JSON.parse(text)
      rescue Timeout::Error, IOError, SystemCallError, SocketError, Net::HTTPBadResponse, OpenSSL::SSL::SSLError
        attempts += 1
        if attempts < 2
          sleep(0.1)
          retry
        end
        raise Unavailable, "Radical ID could not be reached"
      rescue JSON::ParserError
        raise InvalidResponse, "Radical ID returned invalid JSON"
      end
    end

    def profile(data)
      unless data.is_a?(Hash) && %w[issuer sub name email].all? { |k| data[k].is_a?(String) && !data[k].empty? } &&
          data["issuer"].delete_suffix("/") == @origin.to_s.delete_suffix("/") &&
          [ true, false ].include?(data["email_verified"]) && [ true, false ].include?(data["eligible"])
        raise InvalidResponse, "Radical ID returned an invalid profile"
      end
      Profile.new(**Profile.members.to_h { |k| [ k, data[k.to_s]&.freeze ] })
    end

    def transmit(method, uri, headers, body)
      http = Net::HTTP.new(uri.host, uri.port, nil)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = 2
      http.read_timeout = 3
      http.write_timeout = 3
      http.max_retries = 0
      req = { get: Net::HTTP::Get, post: Net::HTTP::Post, put: Net::HTTP::Put }.fetch(method).new(uri.request_uri, headers)
      req.body = body if body
      text = +""
      status = nil
      http.request(req) do |res|
        status = res.code.to_i
        res.read_body do |chunk|
          text << chunk
          raise InvalidResponse, "Radical ID response is too large" if text.bytesize > MAX_RESPONSE_BYTES
        end
      end
      [ status, text ]
    end
  end
end
