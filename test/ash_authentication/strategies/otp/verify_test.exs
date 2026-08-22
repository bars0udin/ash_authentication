# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.VerifyTest do
  @moduledoc false
  # Not `async: true`: the sender reports the code through the logger and
  # `capture_log/1` captures globally, so running concurrently with the other
  # OTP tests would let the two suites read each other's codes.
  use DataCase, async: false

  import ExUnit.CaptureLog

  alias AshAuthentication.{Info, Strategy}

  require Ash.Query

  setup do
    strategy = Info.strategy!(Example.UserWithOtpVerify, :otp)

    user =
      Example.UserWithOtpVerify
      |> Ash.Changeset.for_create(:create, %{
        email: "test_#{System.unique_integer([:positive])}@example.com"
      })
      |> Ash.create!()

    %{strategy: strategy, user: user, email: to_string(user.email)}
  end

  describe "verify" do
    test "a correct code verifies", %{strategy: strategy, email: email} do
      code = request_code(strategy, email)

      assert {:ok, true} =
               Strategy.action(strategy, :verify, %{"email" => email, "otp" => code}, [])
    end

    test "it stores no session token, where signing in does", ctx do
      %{strategy: strategy, user: user, email: email} = ctx
      subject = AshAuthentication.user_to_subject(user)

      assert session_tokens(subject) == 0

      assert {:ok, true} =
               Strategy.action(
                 strategy,
                 :verify,
                 %{"email" => email, "otp" => request_code(strategy, email)},
                 []
               )

      assert session_tokens(subject) == 0

      assert {:ok, _signed_in} =
               Strategy.action(
                 strategy,
                 :sign_in,
                 %{"email" => email, "otp" => request_code(strategy, email)},
                 []
               )

      assert session_tokens(subject) == 1
    end

    test "an incorrect code does not verify", %{strategy: strategy, email: email} do
      _code = request_code(strategy, email)

      assert {:ok, false} =
               Strategy.action(strategy, :verify, %{"email" => email, "otp" => "WRONG1"}, [])
    end

    test "an unknown identity does not verify", %{strategy: strategy} do
      assert {:ok, false} =
               Strategy.action(
                 strategy,
                 :verify,
                 %{
                   "email" => "nobody_#{System.unique_integer([:positive])}@example.com",
                   "otp" => "ABCDEF"
                 },
                 []
               )
    end

    test "a verified code is spent when the strategy is single use", ctx do
      %{strategy: strategy, email: email} = ctx
      code = request_code(strategy, email)

      assert strategy.single_use_token?

      assert {:ok, true} =
               Strategy.action(strategy, :verify, %{"email" => email, "otp" => code}, [])

      assert {:ok, false} =
               Strategy.action(strategy, :verify, %{"email" => email, "otp" => code}, [])
    end

    test "a spent code can no longer be used to sign in", ctx do
      %{strategy: strategy, email: email} = ctx
      code = request_code(strategy, email)

      assert {:ok, true} =
               Strategy.action(strategy, :verify, %{"email" => email, "otp" => code}, [])

      assert {:error, _} =
               Strategy.action(strategy, :sign_in, %{"email" => email, "otp" => code}, [])
    end
  end

  describe "strategy protocol" do
    test "verify is listed among the strategy's actions and phases", %{strategy: strategy} do
      assert :verify in Strategy.actions(strategy)
      assert :verify in Strategy.phases(strategy)
      assert Enum.any?(Strategy.routes(strategy), &match?({_path, :verify}, &1))
    end

    test "it is absent when not enabled" do
      strategy = Info.strategy!(Example.UserWithOtp, :otp)

      refute strategy.verify_enabled?
      refute :verify in Strategy.actions(strategy)
      refute :verify in Strategy.phases(strategy)
      refute Enum.any?(Strategy.routes(strategy), &match?({_path, :verify}, &1))
    end
  end

  defp session_tokens(subject) do
    Example.Token
    |> Ash.Query.filter(subject: subject, purpose: "user")
    |> Ash.count!(authorize?: false)
  end

  defp request_code(strategy, email) do
    log =
      capture_log(fn ->
        :ok = Strategy.action(strategy, :request, %{"email" => email}, [])
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
