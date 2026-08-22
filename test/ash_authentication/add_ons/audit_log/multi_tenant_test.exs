# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.MultiTenantTest do
  @moduledoc false
  use DataCase, async: false

  alias AshAuthentication.AddOn.AuditLog.BruteForceHelpers
  alias AshAuthentication.{AuditLogResource.Batcher, Info, Strategy}

  setup do
    start_supervised!({Batcher, otp_app: :ash_authentication})

    %{
      strategy: Info.strategy!(Example.MultiTenantUserWithAuditLog, :password),
      audit_log: Info.strategy!(Example.MultiTenantUserWithAuditLog, :audit_log),
      tenant_a: Ash.UUID.generate(),
      tenant_b: Ash.UUID.generate(),
      email: "test_#{System.unique_integer([:positive])}@example.com"
    }
  end

  describe "writing to a tenant-scoped audit log" do
    test "records the attempt in the tenant it was made in", ctx do
      %{strategy: strategy, tenant_a: tenant_a, email: email} = ctx

      fail_sign_in(strategy, email, tenant_a)
      Batcher.flush()

      assert count_entries(tenant_a) == 1
    end

    test "does not record one tenant's attempts against another", ctx do
      %{strategy: strategy, tenant_a: tenant_a, tenant_b: tenant_b, email: email} = ctx

      for _ <- 1..3, do: fail_sign_in(strategy, email, tenant_a)
      Batcher.flush()

      assert count_entries(tenant_a) == 3
      assert count_entries(tenant_b) == 0
    end
  end

  describe "counting failures in a tenant-scoped audit log" do
    test "counts only the failures recorded in that tenant", ctx do
      %{strategy: strategy, audit_log: audit_log, email: email} = ctx
      %{tenant_a: tenant_a, tenant_b: tenant_b} = ctx

      for _ <- 1..3, do: fail_sign_in(strategy, email, tenant_a)
      Batcher.flush()

      assert {:ok, 3} = count_failures(audit_log, email, tenant_a)
      assert {:ok, 0} = count_failures(audit_log, email, tenant_b)
    end
  end

  describe "identity-keyed brute force protection" do
    test "one tenant's attempts do not lock the same identity out of another", ctx do
      %{strategy: strategy, tenant_a: tenant_a, tenant_b: tenant_b, email: email} = ctx

      # Past the default maximum of five failures. The reset-request action is
      # keyed on the submitted identity rather than on a resolved user, which is
      # the path on which a bare identity is shared between tenants.
      for _ <- 1..6, do: request_reset(strategy, email, tenant_a)
      Batcher.flush()

      assert {:error, error} = request_reset(strategy, email, tenant_a)
      assert locked_out?(error)

      assert :ok = request_reset(strategy, email, tenant_b)
    end
  end

  defp fail_sign_in(strategy, email, tenant) do
    Strategy.action(strategy, :sign_in, %{"email" => email, "password" => "wrong password"},
      tenant: tenant
    )
  end

  defp request_reset(strategy, email, tenant) do
    Strategy.action(strategy, :reset_request, %{"email" => email}, tenant: tenant)
  end

  defp count_failures(audit_log, email, tenant) do
    BruteForceHelpers.count_failures(
      audit_log,
      [identity: email, strategy: :password, tenant: tenant],
      DateTime.add(DateTime.utc_now(), -3600, :second)
    )
  end

  defp count_entries(tenant) do
    Ash.count!(Example.MultiTenantAuditLog, tenant: tenant, authorize?: false)
  end

  # The brute-force refusal and an ordinary failure are both
  # `AuthenticationFailed` with the same public message, so they are told apart
  # by what caused them rather than by how they read.
  defp locked_out?(error) do
    error
    |> flatten_errors()
    |> Enum.any?(&match?(%{caused_by: %{message: "Too many failed attempts"}}, &1))
  end

  defp flatten_errors(%{errors: errors}) when is_list(errors),
    do: Enum.flat_map(errors, &[&1 | flatten_errors(&1)])

  defp flatten_errors(_error), do: []
end
