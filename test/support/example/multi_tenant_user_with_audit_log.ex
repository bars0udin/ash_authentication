# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.MultiTenantUserWithAuditLog do
  @moduledoc """
  A tenant-scoped user whose brute-force mitigation is a tenant-scoped audit log.
  """
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication],
    domain: Example

  attributes do
    uuid_primary_key :id, writable?: true
    attribute :organisation_id, :uuid, allow_nil?: false, public?: true
    attribute :email, :ci_string, allow_nil?: false, public?: true
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  postgres do
    table "mt_user_with_audit_log"
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
      token_resource Example.Token
      signing_secret &Example.User.get_config/2
    end

    add_ons do
      audit_log do
        audit_log_resource(Example.MultiTenantAuditLog)
        include_fields([:email])
      end
    end

    strategies do
      password do
        identity_field :email
        brute_force_strategy({:audit_log, :audit_log})

        resettable do
          sender fn _user, _token, _opts -> :ok end
        end
      end
    end
  end

  identities do
    identity :unique_email, [:email]
  end
end
