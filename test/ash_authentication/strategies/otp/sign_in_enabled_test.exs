# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.SignInEnabledTest do
  @moduledoc false
  # Not `async: true`: the sender reports the code through the logger and
  # `capture_log/1` captures globally, so running concurrently with the other
  # OTP tests would let the two suites read each other's codes.
  use DataCase, async: false

  import ExUnit.CaptureLog

  alias AshAuthentication.{Info, Strategy}

  describe "sign_in_enabled? false" do
    setup do
      %{strategy: Info.strategy!(Example.UserWithOtp, :code_only)}
    end

    test "generates no sign-in action", %{strategy: strategy} do
      refute strategy.sign_in_enabled?
      refute Ash.Resource.Info.action(strategy.resource, :sign_in_with_code_only)
    end

    test "offers no sign-in phase, action or route", %{strategy: strategy} do
      refute :sign_in in Strategy.actions(strategy)
      refute :sign_in in Strategy.phases(strategy)
      refute Enum.any?(Strategy.routes(strategy), &match?({_path, :sign_in}, &1))
    end

    test "still requests and delivers a code", %{strategy: strategy} do
      user = build_otp_user()

      log =
        capture_log(fn ->
          assert :ok =
                   Strategy.action(strategy, :request, %{"email" => to_string(user.email)}, [])
        end)

      assert log =~ "Code-only request for #{user.email}"
    end
  end

  describe "sign_in_enabled? defaults to true" do
    test "the sign-in action is generated as before" do
      strategy = Info.strategy!(Example.UserWithOtp, :otp)

      assert strategy.sign_in_enabled?
      assert Ash.Resource.Info.action(strategy.resource, :sign_in_with_otp)
      assert :sign_in in Strategy.actions(strategy)
      assert :sign_in in Strategy.phases(strategy)
      assert Enum.any?(Strategy.routes(strategy), &match?({_path, :sign_in}, &1))
    end
  end

  describe "two strategies on one resource" do
    test "a code from one cannot be signed in with through the other" do
      user = build_otp_user()
      email = to_string(user.email)
      code_only = Info.strategy!(Example.UserWithOtp, :code_only)
      otp = Info.strategy!(Example.UserWithOtp, :otp)

      code =
        capture_log(fn ->
          :ok = Strategy.action(code_only, :request, %{"email" => email}, [])
        end)
        |> extract_code("Code-only request for #{email}")

      # The JTI is namespaced by strategy name, so the sign-in strategy cannot
      # find a token minted by the code-only one.
      assert {:error, _} =
               Strategy.action(otp, :sign_in, %{"email" => email, "otp" => code}, [])
    end
  end

  defp build_otp_user do
    Example.UserWithOtp
    |> Ash.Changeset.for_create(:create, %{
      email: "test_#{System.unique_integer([:positive])}@example.com"
    })
    |> Ash.create!()
  end

  defp extract_code(log, marker) do
    log
    |> String.split("\n")
    |> Enum.find(&String.contains?(&1, marker))
    |> String.split("code \"", parts: 2)
    |> Enum.at(1)
    |> String.split("\"", parts: 2)
    |> Enum.at(0)
  end
end
