# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithOtpVerify do
  @moduledoc """
  OTP with the verify action enabled, for checking a code without signing in.
  """
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  require Logger

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :email, :ci_string, allow_nil?: false, public?: true

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  postgres do
    table "user_with_otp_verify"
    repo(Example.Repo)
  end

  actions do
    defaults [:read]

    create :create do
      primary? true
      accept [:email]
    end
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
        verify_enabled? true

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
