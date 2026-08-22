# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.MultiTenantAuditLog do
  @moduledoc """
  A tenant-scoped audit log, so that one tenant's failed attempts are counted
  separately from another's.
  """
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.AuditLogResource],
    domain: Example

  attributes do
    attribute :organisation_id, :uuid, allow_nil?: true, public?: true
  end

  actions do
    defaults [:read]
  end

  multitenancy do
    strategy :attribute
    attribute :organisation_id
  end

  postgres do
    table "mt_audit_logs"
    repo(Example.Repo)
  end
end
