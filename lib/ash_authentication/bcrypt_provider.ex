# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.BcryptProvider do
  @moduledoc """
  Provides the default implementation of `AshAuthentication.HashProvider` using `Bcrypt`.
  """
  @behaviour AshAuthentication.HashProvider

  @doc """
  Given some user input as a string, convert it into it's hashed form using `Bcrypt`.

  ## Example

      iex> {:ok, hashed} = hash("Marty McFly")
      ...> String.starts_with?(hashed, "$2b$04$")
      true
  """
  @impl true
  @spec hash(String.t()) :: {:ok, String.t()} | :error
  if Code.ensure_loaded?(Bcrypt) do
    def hash(input) when is_binary(input), do: {:ok, Bcrypt.hash_pwd_salt(input)}
    def hash(_), do: :error
  else
    def hash(_), do: raise("Bcrypt is not available")
  end

  @doc """
  Check if the user input matches the hash.

  ## Example

      iex> valid?("Marty McFly", "$2b$04$qgacrnrAJz8aPwaVQiGJn.PvryldV.NfOSYYvF/CZAGgMvvzhIE7S")
      true

  """
  @impl true
  @spec valid?(input :: String.t() | nil, hash :: String.t() | nil) :: boolean
  if Code.ensure_loaded?(Bcrypt) do
    def valid?(nil, _hash), do: Bcrypt.no_user_verify()

    # A record which has never had a password set stores no hash, which is an
    # ordinary state rather than a mistake: a user registered through OAuth2, a
    # magic link or an OTP has one. Nothing can match it, and answering in the
    # same time a wrong password takes keeps that indistinguishable.
    def valid?(input, nil) when is_binary(input), do: Bcrypt.no_user_verify()

    def valid?(input, hash) when is_binary(input) and is_binary(hash),
      do: Bcrypt.verify_pass(input, hash)
  else
    def valid?(_input, _hash), do: raise("Bcrypt not available")
  end

  @doc """
  Simulate a password check to help avoid timing attacks.

  ## Example

      iex> simulate()
      false
  """
  @impl true
  @spec simulate :: false
  if Code.ensure_loaded?(Bcrypt) do
    def simulate, do: Bcrypt.no_user_verify()
  else
    def simulate, do: raise("Bcrypt not available")
  end

  @impl true
  @spec minimum_entropy() :: non_neg_integer()
  def minimum_entropy, do: 0

  @impl true
  @spec deterministic?() :: boolean()
  def deterministic?, do: false
end
