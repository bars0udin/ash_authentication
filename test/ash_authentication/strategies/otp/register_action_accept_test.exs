# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.RegisterActionAcceptTest do
  @moduledoc false
  # Not `async: true`: the sender reports the code through the logger and
  # `capture_log/1` captures globally, so running concurrently with the other
  # OTP tests would let the two suites read each other's codes.
  use DataCase, async: false

  import ExUnit.CaptureLog

  alias AshAuthentication.{Info, Strategy}

  setup do
    %{
      strategy: Info.strategy!(Example.UserWithRegisterOtpAccept, :otp),
      email: "test_#{System.unique_integer([:positive])}@example.com"
    }
  end

  describe "register_action_accept" do
    test "the sign-in action accepts the listed fields", %{strategy: strategy} do
      action = Ash.Resource.Info.action(strategy.resource, strategy.sign_in_action_name)

      assert :display_name in action.accept
      assert :accepted_terms_at in action.accept
    end

    test "the listed fields are written when the user is registered", ctx do
      %{strategy: strategy, email: email} = ctx
      accepted_at = DateTime.utc_now()
      otp_code = request_code(strategy, email)

      assert {:ok, user} =
               Strategy.action(
                 strategy,
                 :sign_in,
                 %{
                   "email" => email,
                   "otp" => otp_code,
                   "display_name" => "Marty McFly",
                   "accepted_terms_at" => accepted_at
                 },
                 []
               )

      assert user.display_name == "Marty McFly"
      assert DateTime.compare(user.accepted_terms_at, accepted_at) == :eq
    end

    test "a subsequent sign-in does not clobber them", ctx do
      %{strategy: strategy, email: email} = ctx

      {:ok, _user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{
            "email" => email,
            "otp" => request_code(strategy, email),
            "display_name" => "Marty McFly"
          },
          []
        )

      assert {:ok, user} =
               Strategy.action(
                 strategy,
                 :sign_in,
                 %{"email" => email, "otp" => request_code(strategy, email)},
                 []
               )

      assert user.display_name == "Marty McFly"
    end

    test "defaults to accepting nothing beyond the strategy's own arguments" do
      strategy = Info.strategy!(Example.UserWithRegisterOtp, :otp)
      action = Ash.Resource.Info.action(strategy.resource, strategy.sign_in_action_name)

      assert strategy.register_action_accept == []
      assert action.accept == []
    end
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
