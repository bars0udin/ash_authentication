# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Password.PasswordValidationTest do
  @moduledoc false
  use DataCase, async: true
  alias Ash.Changeset
  alias Ash.Resource.Validation.Negate
  alias AshAuthentication.{Errors.AuthenticationFailed, Strategy.Password.PasswordValidation}

  describe "validate/2" do
    test "when provided with a correct password it validates" do
      user = build_user()

      assert :ok =
               user
               |> Changeset.new()
               |> Changeset.set_argument(:current_password, user.__metadata__.password)
               |> PasswordValidation.validate(
                 [
                   strategy_name: :password,
                   password_argument: :current_password
                 ],
                 %{}
               )
    end

    test "when provided with an incorrect password, it fails vailidation" do
      user = build_user()

      assert {:error, %AuthenticationFailed{field: :current_password}} =
               user
               |> Changeset.new()
               |> Changeset.set_argument(:current_password, "wrong password")
               |> PasswordValidation.validate(
                 [
                   strategy_name: :password,
                   password_argument: :current_password
                 ],
                 %{}
               )
    end
  end

  describe "describe/1" do
    test "it is exported, so the validation can be wrapped by `negate/1`" do
      assert {:ok, opts} =
               Negate.init(
                 validation:
                   {PasswordValidation,
                    [strategy_name: :password, password_argument: :current_password]}
               )

      assert [message: message, vars: []] = Negate.describe(opts)
      assert message =~ "must not pass validation"
    end

    test "negated, it passes for a password which is not the current one" do
      user = build_user()

      {:ok, opts} =
        Negate.init(
          validation:
            {PasswordValidation, [strategy_name: :password, password_argument: :current_password]}
        )

      changeset =
        user
        |> Changeset.new()
        |> Changeset.set_argument(:current_password, "a different password")

      assert :ok = Negate.validate(changeset, opts, %{})
    end

    test "negated, it fails for the password which is the current one" do
      user = build_user()

      {:ok, opts} =
        Negate.init(
          validation:
            {PasswordValidation, [strategy_name: :password, password_argument: :current_password]}
        )

      changeset =
        user
        |> Changeset.new()
        |> Changeset.set_argument(:current_password, user.__metadata__.password)

      assert {:error, _reused} = Negate.validate(changeset, opts, %{})
    end
  end
end
