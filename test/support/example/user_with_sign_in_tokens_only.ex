# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithSignInTokensOnly do
  @moduledoc """
  A password strategy which mounts no sign in route but still exchanges
  short-lived sign in tokens for a session.

  The shape an application reaches for when the credential check happens
  somewhere it controls — behind a second factor, or through an action of its
  own — and the strategy's own `POST /auth/<subject>/password/sign_in` would be
  a way round it.
  """
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  attributes do
    uuid_primary_key :id, writable?: true

    attribute :username, :ci_string, allow_nil?: false, public?: true
    attribute :hashed_password, :string, allow_nil?: false, sensitive?: true

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  postgres do
    table "user_with_sign_in_tokens_only"
    repo(Example.Repo)
  end

  actions do
    defaults [:read]

    create :register do
      accept [:username]
      argument :password, :string, allow_nil?: false, sensitive?: true

      change {AshAuthentication.Strategy.Password.HashPasswordChange, strategy_name: :password}
    end
  end

  authentication do
    tokens do
      enabled? true
      token_resource Example.Token
      signing_secret &Example.User.get_config/2
    end

    strategies do
      password :password do
        identity_field :username
        registration_enabled? false
        sign_in_enabled? false
        sign_in_tokens_enabled? true
      end
    end
  end

  identities do
    identity :unique_username, [:username]
  end
end
