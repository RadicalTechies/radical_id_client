# Radical ID Client

A Ruby client for Radical ID's application-scoped directory API, plus optional
Rails 8.1 administration components. Ruby 3.3+; AGPL-3.0-only.

```ruby
require "radical_id_client"
client = RadicalIdClient::Client.new(origin: ENV.fetch("OIDC_ISSUER"),
  token: ENV.fetch("RADICAL_ID_API_TOKEN"))
profile = client.lookup_user(email: "person@example.org", actor_sub: administrator_sub)
profile = client.fetch_user(sub: profile.sub, actor_sub: administrator_sub)
client.ensure_application_access(sub: profile.sub, actor_sub: administrator_sub)
```

Credentials are issued in Radical ID's application administration, with optional
grant capability, 90-day expiry and immediate revocation. A credential reaches
only its own application's grants. The actor subject is the calling application's
audit assertion; the caller must authenticate and authorize its administrator.
Never send this credential to a browser or reuse an OIDC client secret.

The client validates a fixed HTTPS origin and issuer, does not follow redirects,
bounds responses to 64 KiB, and sets 2-second connect and 3-second read/write
timeouts. Network failures get one delayed retry; HTTP errors do not retry.
Exceptions distinguish configuration, authentication, authorization, missing users,
ineligibility, conflicts, rate limits, malformed responses and outages. Profiles
carry only the API's explicit claims. No profile cache or background synchronization.

Inject `transport:` for offline tests: it receives `(method, uri, headers, json_body)`
and returns `[status_integer, response_body]`. `bundle exec rake` tests the client.

## Rails integration

Require `radical_id_client/rails` in the Gemfile (before Rails initialization),
mount `RadicalIdClient::Rails::Engine` at `/identity_admin`, and configure an
application-specific subclass of `RadicalIdClient::Rails::Adapter` in `to_prepare`.
The ten RadicalTechies Rails apps provide working adapters and migrations. The
host supplies identity keys, active/admin policy, local membership controls and
landing routes; the client never maps a remote role into local privileges.

Install `SessionGuard` after Rails session middleware and before OmniAuth so
mounted engines and provider request phases receive the same restrictions. Render
`radical_id_client/rails/banner` in web layouts (never mailer layouts). The engine
has its own CSRF-protected admin controllers and does not inherit a tenant scope.

The `radical_id_impersonations` and `radical_id_admin_events` tables retain the real
actor and effective identity. Use UUID actor/target columns when the host uses UUID
user IDs. Session changes preserve the original authentication deadline. Separate
signed login cookies are also checked against impersonation records, so dropping
the Rails cookie cannot turn an impersonation into a normal login. The guard covers
nested credential and membership routes. Hosts can extend blocked paths.

The administration flow uses a signed, actor-bound, ten-minute profile review and
re-fetches the identity before an idempotent central grant. Local persistence occurs
in a transaction; a failure after the central grant is surfaced for safe retry.
An existing account is matched by immutable identity; verified email may adopt only
an unbound provisional record. Identity conflicts fail closed.

Release through a reviewed PR, tag the reviewed commit, and pin consuming apps to
that immutable revision. Shared Rails behavior is exercised by the consuming apps'
DevContainer integration suites, including CSRF, expiration, role revocation,
provisioning conflicts, browser cookie separation and Helpdesk customer access.
