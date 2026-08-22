<!--
SPDX-FileCopyrightText: 2026 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# OTP (One-Time Password) Tutorial

The OTP strategy provides passwordless authentication where users receive a short code (e.g. `"XKPTMH"`) via email or SMS, then submit it to sign in. This is similar to the magic link strategy but uses a short code instead of a URL.

> #### Time-based one-time passwords {: .tip}
>
> If you're looking for the six-digit numeric codes which periodically change - sometimes
> called Google Authenticator - you almost certainly want [TOTP](tutorials/totp.md) instead.

## Security requirements

> #### Brute force protection {: .warning}
>
> OTP codes have limited entropy by design — short codes that users can type without error.
> Without rate limiting, an attacker can enumerate all possible codes within the lifetime
> of a single OTP.
>
> For this reason, the OTP strategy **requires** you to declare a `brute_force_strategy`
> at the DSL level. The verifier will fail compilation if the declared strategy is not
> actually wired up to the request and sign-in actions.
>
> A 10-minute OTP lifetime with 6 uppercase letters gives ~85 million possible codes.
> Even so, restricting to a handful of attempts per identity per OTP lifetime is essential.

### Choosing a brute force strategy

The `brute_force_strategy` option accepts one of:

- `:rate_limit` — defers to the [`AshRateLimiter`](https://hexdocs.pm/ash_rate_limiter)
  extension on the same resource. The verifier checks that the extension is present
  and that every OTP action has a `rate_limit` entry.
- `{:audit_log, :audit_log_name}` — tracks failed attempts in an audit log add-on
  and blocks after `audit_log_max_failures` within `audit_log_window`.
- `{:preparation, MyApp.BruteForceMitigation}` — plug in a custom
  `Ash.Resource.Preparation` implementation and take full control.

Example using rate limiting:

```elixir
use Ash.Resource, extensions: [AshAuthentication, AshRateLimiter]

authentication do
  strategies do
    otp do
      identity_field :email
      brute_force_strategy :rate_limit
      sender MyApp.Accounts.User.Senders.SendOtp
    end
  end
end

rate_limit do
  backend MyApp.RateLimiterBackend

  action :request_otp,
    limit: 5,
    per: :timer.minutes(15),
    key: fn query -> "otp:request:#{query.arguments[:email]}" end

  action :sign_in_with_otp,
    limit: 5,
    per: :timer.minutes(10),
    key: fn query -> "otp:sign_in:#{query.arguments[:email]}" end
end
```

> #### Scope the rate limit bucket by identity {: .warning}
>
> `AshRateLimiter`'s default bucket key is the domain + resource + action name, which
> means **a single global bucket is shared by all callers**. Without a `key` function,
> once any 5 callers hit `sign_in_with_otp` in 10 minutes the 6th is blocked —
> regardless of whose email they supplied. That both lets an attacker DoS the entire
> app by burning the bucket and fails to stop them from enumerating a single victim's
> code.
>
> Always supply a `key` function that scopes by the `identity_field` argument, as in
> the example above.

Example using an audit log:

```elixir
authentication do
  strategies do
    otp do
      identity_field :email
      brute_force_strategy {:audit_log, :auth_audit_log}
      audit_log_window {5, :minutes}
      audit_log_max_failures 5
      sender MyApp.Accounts.User.Senders.SendOtp
    end
  end

  add_ons do
    audit_log :auth_audit_log do
      audit_log_resource MyApp.Accounts.AuthAuditLog
    end
  end
end
```

The audit log add-on tracks all authentication actions by default, so there's no
need to list them explicitly — failures on `request_otp` and `sign_in_with_otp`
will both count toward the `audit_log_max_failures` threshold.

## Prerequisites

Your user resource needs:

1. A primary key
2. A uniquely constrained identity field (e.g. `email`)
3. Tokens enabled with `store_all_tokens?` set to `true`

## Add the OTP strategy to the User resource

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication, AshRateLimiter],
    domain: MyApp.Accounts

  attributes do
    uuid_primary_key :id
    attribute :email, :ci_string, allow_nil?: false
  end

  authentication do
    tokens do
      enabled? true
      store_all_tokens? true
      token_resource MyApp.Accounts.Token
      signing_secret MyApp.Secrets
    end

    strategies do
      otp do
        identity_field :email
        brute_force_strategy :rate_limit
        sender MyApp.Accounts.User.Senders.SendOtp
      end
    end
  end

  # Per-identity rate limiting — see "Choosing a brute force strategy" above
  # for the reasoning behind scoping the bucket by email.
  rate_limit do
    backend MyApp.RateLimiterBackend

    action :request_otp,
      limit: 5,
      per: :timer.minutes(15),
      key: fn query -> "otp:request:#{query.arguments[:email]}" end

    action :sign_in_with_otp,
      limit: 5,
      per: :timer.minutes(10),
      key: fn query -> "otp:sign_in:#{query.arguments[:email]}" end
  end

  identities do
    identity :unique_email, [:email]
  end
end
```

## Configuration options

The strategy supports several options with sensible defaults:

```elixir
otp do
  identity_field :email
  otp_lifetime {10, :minutes}          # how long the code is valid
  otp_length 6                         # length of the generated code
  otp_characters :unambiguous_uppercase # :unambiguous_uppercase, :unambiguous_alphanumeric, :digits_only, :uppercase_letters_only
  case_sensitive? false                 # when false, "xkptmh" matches "XKPTMH"
  single_use_token? true               # revoke code after successful sign-in
  sender MyApp.Accounts.User.Senders.SendOtp
end
```

## Create an OTP sender

The sender receives the user record and the short OTP code (not a JWT). You are responsible for delivering it to the user.

Inside `lib/my_app/accounts/user/senders/send_otp.ex`:

```elixir
defmodule MyApp.Accounts.User.Senders.SendOtp do
  @moduledoc """
  Sends a one-time password code to the user.
  """
  use AshAuthentication.Sender

  @impl AshAuthentication.Sender
  def send(user, otp_code, _opts) do
    MyApp.Accounts.Emails.deliver_otp(user.email, otp_code)
  end
end
```

Inside `lib/my_app/accounts/emails.ex`:

```elixir
def deliver_otp(email, otp_code) do
  deliver(email, "Your sign-in code", """
  <html>
    <p>Your sign-in code is:</p>
    <p style="font-size: 24px; font-weight: bold; letter-spacing: 4px;">#{otp_code}</p>
    <p>This code expires in 10 minutes.</p>
  </html>
  """)
end
```

You can also use an inline function sender for simple cases:

```elixir
sender fn user, otp_code, _opts ->
  MyApp.Accounts.Emails.deliver_otp(user.email, otp_code)
end
```

## Registration

By default, the OTP strategy only allows existing users to sign in. To allow new users to register via OTP, set `registration_enabled?` to `true`:

```elixir
otp do
  identity_field :email
  registration_enabled? true
  sender MyApp.Accounts.User.Senders.SendOtp
end
```

When registration is enabled:

- The **request** action sends an OTP code even if no user with that email exists yet.
- The **sign-in** action becomes a `:create` action with `upsert? true`. If the user doesn't exist, they are created; if they do, they are matched by their identity.
- `{:audit_log, ...}` is **not** a valid `brute_force_strategy` in this mode, because audit log mitigation requires an existing user record. Use `:rate_limit` or `{:preparation, MyModule}` instead.
- The sign-in action accepts nothing beyond the identity and the code unless you list additional fields in `register_action_accept` (see below).
- The sender receives the email address as a string (instead of a user record) when the user doesn't exist yet. Handle both cases in your sender:

```elixir
def send(user_or_email, otp_code, _opts) do
  email =
    case user_or_email do
      %{email: email} -> email
      email when is_binary(email) -> email
    end

  MyApp.Accounts.Emails.deliver_otp(email, otp_code)
end
```

### Collecting extra fields at registration

A registration is often the only moment you can collect something — a display
name, or the timestamp at which terms were accepted. `register_action_accept`
adds those fields to the sign-in action's accept list, mirroring the option of
the same name on the password strategy:

```elixir
otp do
  identity_field :email
  registration_enabled? true
  register_action_accept [:display_name, :accepted_terms_at]
  sender MyApp.Accounts.User.Senders.SendOtp
end
```

The fields are written when the user is created. They are *not* added to
`upsert_fields`, so an existing user signing in again keeps the values they
registered with rather than having them rewritten from whatever the sign-in form
submitted. It defaults to `[]`, so a strategy that does not set it behaves
exactly as before.

### Registration on a multitenant resource

When the user resource is multitenant and its identity is scoped to a single
tenant — which is the default; an identity is only shared across tenants when it
is declared `all_tenants? true` — the same identity value names a different user
in each tenant. The strategy accounts for this: the JTI it derives for a
registration code includes the tenant the request was made for, so a code issued
in one tenant cannot be redeemed in another.

Nothing needs to be configured for this. It follows from the resource's own
`multitenancy` and `identities` declarations, and applies equally to the
`:attribute` and `:context` multitenancy strategies. You do need to pass the
tenant to both the request and the sign-in action, exactly as you would for any
other action on a multitenant resource:

```elixir
:ok = AshAuthentication.Strategy.action(strategy, :request, %{"email" => email},
  tenant: tenant)

{:ok, user} = AshAuthentication.Strategy.action(strategy, :sign_in,
  %{"email" => email, "otp" => code}, tenant: tenant)
```

> **Note:** If you don't define a sign-in action yourself, the strategy auto-generates the correct one at compile time and changing `registration_enabled?` just works. However, if you have a sign-in action defined in your resource file (whether written by hand or generated by an installer), it is **not** regenerated automatically. If you change `registration_enabled?`, you must update the action yourself: use a `:create` action with `AshAuthentication.Strategy.Otp.SignInChange` when `true`, or a `:read` action with `AshAuthentication.Strategy.Otp.SignInPreparation` when `false`. The verifier will raise if there's a mismatch.

## How it works

The OTP strategy uses a deterministic JTI (JWT ID) to map short codes back to stored tokens without requiring any schema changes to your token resource. The JTI is derived from `(strategy_name, user_subject, otp_code)` via `AshAuthentication.SHA256Provider`, keeping the crypto consistent with the recovery code strategy.

When `registration_enabled?` is set there is no user to take a subject from, so the JTI is derived from `(strategy_name, identity, otp_code)` instead — plus the tenant, when the resource's identity is tenant-scoped.

**Request flow:**

1. User submits their email
2. Strategy finds the user, generates a random OTP code
3. A JWT is created with a deterministic JTI derived from `(strategy_name, user_subject, otp_code)`
4. The JWT is stored in the token resource with purpose `"otp"`
5. The short code is sent to the user via the sender
6. Returns `:ok` regardless of whether the user exists (never reveals user existence)

**Sign-in flow:**

1. User submits their email and OTP code
2. Strategy finds the user, recomputes the deterministic JTI from the submitted code
3. Looks up the token by JTI and purpose `"otp"`
4. If found: code is valid. Revokes the token (if `single_use_token?`), generates an auth JWT, returns the user
5. If not found: authentication fails

## Verifying a code without signing in

Sometimes a code needs to authorise something that is not a session: confirming
a change of phone number, or stepping up to an operation the current session is
not sufficient for on its own. Set `verify_enabled? true` to generate an action
which checks a code and answers a boolean:

```elixir
otp do
  identity_field :email
  verify_enabled? true
  sender MyApp.Accounts.User.Senders.SendOtp
end
```

```elixir
{:ok, true} = AshAuthentication.Strategy.action(strategy, :verify, %{
  "email" => "user@example.com",
  "otp" => "XKPTMH"
})
```

It defaults to `false`, so an existing strategy gains no new action unless it
asks for one. The action is named `verify_with_<strategy_name>` unless
`verify_action_name` says otherwise, and is exposed at
`POST /auth/<subject>/<strategy>/verify`.

Two things to know about it:

- An unknown identity answers `{:ok, false}` rather than an error, so
  verification cannot be used to find out who has an account.
- A verified code is **spent** when `single_use_token?` is set, which it is by
  default — exactly as signing in with that code would spend it. A verify action
  which left a single-use code live would make `single_use_token?` untrue, and
  the code would stay replayable for the rest of its lifetime.

This differs from the TOTP strategy's verify action, which takes the user whose
secret to check. A TOTP secret lives on a user record; an OTP code is looked up
by the identity it was sent to, so this action takes the same arguments the
strategy's own sign-in action does.

### Codes which can never become a session

Set `sign_in_enabled? false` to remove the sign-in action and route entirely,
leaving a code channel which can only ever be verified:

```elixir
otp :sign_in_code do
  identity_field :email
  sender MyApp.Accounts.User.Senders.SendSignInCode
end

otp :password_reset_code do
  identity_field :email
  sign_in_enabled? false
  verify_enabled? true
  sender MyApp.Accounts.User.Senders.SendResetCode
end
```

Two things follow from declaring more than one OTP strategy, which is how you
give each purpose its own codes:

- **Each strategy is its own namespace.** The stored token's JTI is derived from
  the strategy name among other things, so a code issued by `:password_reset_code`
  simply cannot be found by `:sign_in_code`, and vice versa. A code delivered for
  one purpose is not spendable on another.
- **Each has its own actions, routes and lifetime**, so a reset code can be
  shorter-lived than a sign-in code, and can be delivered differently.

`sign_in_enabled?` defaults to `true`, so an existing strategy is unaffected.

## Using the strategy programmatically

```elixir
strategy = AshAuthentication.Info.strategy!(MyApp.Accounts.User, :otp)

# Request an OTP code (sends email)
:ok = AshAuthentication.Strategy.action(strategy, :request, %{
  "email" => "user@example.com"
})

# Sign in with the code
{:ok, user} = AshAuthentication.Strategy.action(strategy, :sign_in, %{
  "email" => "user@example.com",
  "otp" => "XKPTMH"
})

# The auth JWT is available in metadata
token = user.__metadata__.token
```

## HTTP endpoints

When using `AshAuthentication.Plug`, the strategy automatically registers two POST routes:

```
POST /user/otp/request    {"user": {"email": "user@example.com"}}
POST /user/otp/sign_in    {"user": {"email": "user@example.com", "otp": "XKPTMH"}}
```

## Character sets and entropy

The built-in character sets and the number of possible codes they produce at the default length of 6:

| Option | Symbols | Codes at length 6 | Notes |
|---|---|---|---|
| `:unambiguous_uppercase` (default) | 21 | ~85.8 million | A–Z minus I, L, O, S, Z |
| `:unambiguous_alphanumeric` | 27 | ~387 million | above plus 3,4,6,7,8,9 |
| `:uppercase_letters_only` | 26 | ~309 million | full A–Z |
| `:digits_only` | 10 | 1 million | full 0–9; only just meets the minimum at length 6 |

The strategy enforces a minimum of 1,000,000 possible codes at compile time (derived from NIST SP 800-63B §5.1.3.2). Configurations that fall below this threshold — such as `:digits_only` with `otp_length` less than 6 — will raise a `Spark.Error.DslError` at compile time.

## Custom OTP generator

By default, the strategy uses `AshAuthentication.Strategy.Otp.DefaultGenerator` which generates cryptographically random codes from an ambiguity-reduced character set (excluding easily misread characters like `I`/`1`, `O`/`0`, `S`/`5`, `Z`/`2`).

You can supply your own generator module:

```elixir
otp do
  identity_field :email
  otp_generator MyApp.Accounts.OtpGenerator
  sender MyApp.Accounts.User.Senders.SendOtp
end
```

The module must export `generate/1` and `normalize/1`:

```elixir
defmodule MyApp.Accounts.OtpGenerator do
  def generate(opts) do
    length = Keyword.get(opts, :length, 6)
    # your implementation here
  end

  def normalize(code) do
    String.trim(code)
  end
end
```

The `generate/1` function receives `[length: ..., characters: ...]` from the strategy configuration. The `normalize/1` function is called on both the generated code (during request) and the submitted code (during sign-in) to ensure consistent matching.

> #### Security responsibility {: .warning}
>
> When using a custom generator, the compile-time entropy check is skipped — the
> strategy cannot reason about the code space your implementation produces. It is
> your responsibility to ensure the generator meets your system's security
> requirements, including sufficient entropy, cryptographically secure randomness,
> and correct handling of the `length` and `characters` opts.

## Differences from Magic Links

| | Magic Link | OTP |
|---|---|---|
| **User receives** | A URL with a JWT | A short code (e.g. `XKPTMH`) |
| **Sign-in requires** | Just the token (from URL) | Both identity field and code |
| **UX pattern** | Click link in email | Enter code on same page |
| **Registration** | Can register new users | Can register new users (opt-in) |
| **Interaction required** | Optional (configurable) | Always (user must type code) |
