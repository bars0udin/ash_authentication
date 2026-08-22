# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.VerifyAction do
  @moduledoc """
  Implementation of the OTP verify action.

  Checks a submitted OTP code and answers `{:ok, true}` or `{:ok, false)`
  without minting a session, so that a code can authorise something other than
  signing in — confirming a change of contact details, or stepping up to a
  sensitive operation the current session is not sufficient for.

  Unlike `AshAuthentication.Strategy.Totp.VerifyAction`, which takes the user
  whose secret to check, this takes the same arguments the strategy's own
  sign-in action does — the identity field and the OTP parameter — because an
  OTP code is looked up by the identity it was sent to rather than by a secret
  stored on a record.

  A verified code is **spent** when the strategy is `single_use_token?` (the
  default), exactly as signing in with it would spend it. A verify action that
  left a single-use code live would make `single_use_token?` untrue for anyone
  who enabled this, and the code would remain replayable for the rest of its
  lifetime.
  """
  use Ash.Resource.Actions.Implementation

  alias Ash.{ActionInput, Query}
  alias AshAuthentication.{Info, Strategy.Otp}
  alias AshAuthentication.Strategy.Otp.SignInHelpers

  require Ash.Query
  import Ash.Expr

  @doc false
  @impl true
  def run(input, _opts, context) do
    strategy = Info.strategy_for_action!(input.resource, input.action.name)
    identity = ActionInput.get_argument(input, strategy.identity_field)
    otp_code = ActionInput.get_argument(input, strategy.otp_param_name)
    context_opts = Ash.Context.to_opts(context)

    if is_nil(identity) or is_nil(otp_code) do
      {:ok, false}
    else
      verify(strategy, identity, otp_code, context_opts)
    end
  end

  defp verify(strategy, identity, otp_code, context_opts) do
    token_resource = Info.authentication_tokens_token_resource!(strategy.resource)

    with {:ok, jti, subject} <- jti_for(strategy, identity, otp_code, context_opts) do
      # Generic actions are not transactional by default, so the lock and the
      # revocation are wrapped explicitly to prevent two concurrent
      # verifications both succeeding on the same code.
      token_resource
      |> Ash.transaction(fn ->
        consume(strategy, token_resource, jti, subject, context_opts)
      end)
      |> case do
        {:ok, result} -> result
        {:error, _} -> {:ok, false}
      end
    end
  end

  defp consume(strategy, token_resource, jti, subject, context_opts) do
    with {:ok, [_ | _]} <- SignInHelpers.get_otp_token_locked(token_resource, jti, context_opts),
         :ok <- SignInHelpers.consume_token(strategy, token_resource, jti, subject, context_opts) do
      {:ok, true}
    else
      _ -> {:ok, false}
    end
  end

  # With `registration_enabled?` the code is keyed on the identity, because the
  # user may not exist. Without it the code is keyed on the user's subject, so
  # the user has to be found first — and an identity nobody holds simply does
  # not verify.
  defp jti_for(%{registration_enabled?: true} = strategy, identity, otp_code, context_opts) do
    {:ok,
     Otp.compute_deterministic_jti_for_identity(
       strategy,
       to_string(identity),
       Otp.normalize_otp(strategy, otp_code),
       Keyword.get(context_opts, :tenant)
     ), nil}
  end

  defp jti_for(strategy, identity, otp_code, context_opts) do
    case lookup_user(strategy, identity, context_opts) do
      {:ok, user} when not is_nil(user) ->
        subject = AshAuthentication.user_to_subject(user)

        {:ok,
         Otp.compute_deterministic_jti(
           strategy,
           subject,
           Otp.normalize_otp(strategy, otp_code)
         ), subject}

      _ ->
        {:ok, false}
    end
  end

  defp lookup_user(strategy, identity, context_opts) do
    strategy.resource
    |> Query.new()
    |> Query.set_context(%{private: %{ash_authentication?: true}})
    |> Query.for_read(
      strategy.lookup_action_name,
      %{strategy.identity_field => identity},
      context_opts
    )
    |> Query.filter(^ref(strategy.identity_field) == ^identity)
    |> Ash.read_one()
  end
end
