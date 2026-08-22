# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.MultiTenantTest do
  @moduledoc false
  # Not `async: true`: the sender reports the code through the logger and
  # `capture_log/1` captures globally, so running concurrently with the other
  # OTP tests would let the two suites read each other's codes.
  use DataCase, async: false

  import ExUnit.CaptureLog

  alias AshAuthentication.{Info, Strategy, Strategy.Otp}

  setup do
    %{
      strategy: Info.strategy!(Example.MultiTenantUserWithRegisterOtp, :otp),
      tenant_a: Ash.UUID.generate(),
      tenant_b: Ash.UUID.generate(),
      email: "test_#{System.unique_integer([:positive])}@example.com"
    }
  end

  describe "registration with a tenant-scoped identity" do
    test "a code requested in one tenant does not sign its holder in to another", ctx do
      %{strategy: strategy, tenant_a: tenant_a, tenant_b: tenant_b, email: email} = ctx

      otp_code = request_code(strategy, email, tenant: tenant_a)

      assert {:error, _} =
               Strategy.action(
                 strategy,
                 :sign_in,
                 %{"email" => email, "otp" => otp_code},
                 tenant: tenant_b
               )
    end

    test "a code requested in a tenant signs its holder in to that tenant", ctx do
      %{strategy: strategy, tenant_a: tenant_a, email: email} = ctx

      otp_code = request_code(strategy, email, tenant: tenant_a)

      assert {:ok, user} =
               Strategy.action(
                 strategy,
                 :sign_in,
                 %{"email" => email, "otp" => otp_code},
                 tenant: tenant_a
               )

      assert to_string(user.email) == email
      assert user.organisation_id == tenant_a
      assert user.__metadata__[:token]
    end

    test "the same identity in two tenants is two users with two codes", ctx do
      %{strategy: strategy, tenant_a: tenant_a, tenant_b: tenant_b, email: email} = ctx

      code_a = request_code(strategy, email, tenant: tenant_a)
      code_b = request_code(strategy, email, tenant: tenant_b)

      assert {:ok, user_a} =
               Strategy.action(strategy, :sign_in, %{"email" => email, "otp" => code_a},
                 tenant: tenant_a
               )

      assert {:ok, user_b} =
               Strategy.action(strategy, :sign_in, %{"email" => email, "otp" => code_b},
                 tenant: tenant_b
               )

      refute user_a.id == user_b.id
    end
  end

  describe "compute_deterministic_jti_for_identity/4" do
    test "a tenant-scoped identity hashes differently per tenant", ctx do
      %{strategy: strategy, tenant_a: tenant_a, tenant_b: tenant_b} = ctx

      refute Otp.compute_deterministic_jti_for_identity(
               strategy,
               "marty@mcfly.me",
               "ABCDEF",
               tenant_a
             ) ==
               Otp.compute_deterministic_jti_for_identity(
                 strategy,
                 "marty@mcfly.me",
                 "ABCDEF",
                 tenant_b
               )
    end

    test "a resource which is not multitenant is unaffected by a tenant argument" do
      strategy = Info.strategy!(Example.UserWithRegisterOtp, :otp)

      assert Otp.compute_deterministic_jti_for_identity(strategy, "marty@mcfly.me", "ABCDEF") ==
               Otp.compute_deterministic_jti_for_identity(
                 strategy,
                 "marty@mcfly.me",
                 "ABCDEF",
                 Ash.UUID.generate()
               )
    end

    test "the three-arity form is unchanged", ctx do
      %{strategy: strategy} = ctx

      assert Otp.compute_deterministic_jti_for_identity(strategy, "marty@mcfly.me", "ABCDEF") ==
               Otp.compute_deterministic_jti_for_identity(
                 strategy,
                 "marty@mcfly.me",
                 "ABCDEF",
                 nil
               )
    end
  end

  defp request_code(strategy, email, opts) do
    log =
      capture_log(fn ->
        :ok = Strategy.action(strategy, :request, %{"email" => email}, opts)
      end)

    log
    |> String.split("\n")
    |> Enum.find(&String.contains?(&1, "OTP request for #{email},"))
    |> String.split("code \"", parts: 2)
    |> Enum.at(1)
    |> String.split("\"", parts: 2)
    |> Enum.at(0)
  end
end
