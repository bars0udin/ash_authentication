# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Password.SignInTokensOnlyTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{Info, Jwt, Strategy}

  setup do
    {:ok, strategy} = Info.strategy(Example.UserWithSignInTokensOnly, :password)
    %{strategy: strategy}
  end

  describe "a strategy with sign_in_enabled? false and sign_in_tokens_enabled? true" do
    test "mounts no sign in route", %{strategy: strategy} do
      phases = Strategy.phases(strategy)

      refute :sign_in in phases
      assert :sign_in_with_token in phases

      refute Enum.any?(Strategy.routes(strategy), &(elem(&1, 0) == :sign_in))
    end

    test "generates no sign in action" do
      refute Ash.Resource.Info.action(Example.UserWithSignInTokensOnly, :sign_in_with_password)
      assert Ash.Resource.Info.action(Example.UserWithSignInTokensOnly, :sign_in_with_token)
    end

    test "still exchanges a sign in token for a user", %{strategy: strategy} do
      username = "marty_#{System.unique_integer([:positive])}"

      user =
        Example.UserWithSignInTokensOnly
        |> Ash.Changeset.for_create(:register, %{username: username, password: "so heavy"})
        |> Ash.create!()

      {:ok, token, _claims} =
        Jwt.token_for_user(user, %{"purpose" => "sign_in"},
          token_lifetime: strategy.sign_in_token_lifetime,
          purpose: :sign_in
        )

      assert {:ok, signed_in} =
               Strategy.action(strategy, :sign_in_with_token, %{"token" => token}, [])

      assert signed_in.id == user.id
      assert is_binary(signed_in.__metadata__.token)
    end
  end
end
