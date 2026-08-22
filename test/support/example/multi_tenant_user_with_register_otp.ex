# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.MultiTenantUserWithRegisterOtp do
  @moduledoc """
  A tenant-scoped resource using OTP with registration enabled.

  Unlike the resources in `ExampleMultiTenant`, this one is deliberately *not*
  `global?`, and its `unique_email` identity is deliberately not
  `all_tenants?`, so the same email address in two different tenants is two
  different users. Its token resource is the platform-global `Example.Token`,
  which is the arrangement that makes tenant-blind bookkeeping observable.
  """
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  require Logger

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :organisation_id, :uuid, allow_nil?: false, public?: true
    attribute :email, :ci_string, allow_nil?: false, public?: true

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  postgres do
    table "mt_user_with_register_otp"
    repo(Example.Repo)
  end

  multitenancy do
    strategy :attribute
    attribute :organisation_id
  end

  actions do
    defaults [:read]
  end

  authentication do
    select_for_senders([:email])
    session_identifier(:jti)

    tokens do
      enabled? true
      store_all_tokens? true
      token_resource Example.Token
      signing_secret &Example.User.get_config/2
    end

    strategies do
      otp do
        identity_field :email
        brute_force_strategy({:preparation, Example.TotpNoopPreparation})
        registration_enabled? true

        sender fn user_or_email, otp_code, _opts ->
          email = if is_binary(user_or_email), do: user_or_email, else: user_or_email.email
          Logger.info("OTP request for #{email}, code #{inspect(otp_code)}")
        end
      end
    end
  end

  identities do
    identity :unique_email, [:email]
  end
end
