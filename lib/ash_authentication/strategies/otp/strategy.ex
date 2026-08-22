# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defimpl AshAuthentication.Strategy, for: AshAuthentication.Strategy.Otp do
  @moduledoc false
  alias AshAuthentication.{Info, Strategy, Strategy.Otp}
  alias Plug.Conn

  @doc false
  @spec name(Otp.t()) :: atom
  def name(strategy), do: strategy.name

  @doc false
  @spec phases(Otp.t()) :: [Strategy.phase()]
  def phases(strategy), do: available_actions(strategy)

  @doc false
  @spec actions(Otp.t()) :: [Strategy.action()]
  def actions(strategy), do: available_actions(strategy)

  @doc false
  @spec method_for_phase(Otp.t(), atom) :: Strategy.http_method()
  def method_for_phase(_strategy, :request), do: :post
  def method_for_phase(_strategy, :sign_in), do: :post
  def method_for_phase(_strategy, :verify), do: :post

  @doc false
  @spec routes(Otp.t()) :: [Strategy.route()]
  def routes(strategy) do
    subject_name = Info.authentication_subject_name!(strategy.resource)
    base = "/#{subject_name}/#{strategy.name}"

    [{"#{base}/request", :request}]
    |> maybe_add(strategy.sign_in_enabled?, {"#{base}/sign_in", :sign_in})
    |> maybe_add(strategy.verify_enabled?, {"#{base}/verify", :verify})
  end

  @doc false
  @spec plug(Otp.t(), Strategy.phase(), Conn.t()) :: Conn.t()
  def plug(strategy, :request, conn), do: Otp.Plug.request(conn, strategy)
  def plug(strategy, :sign_in, conn), do: Otp.Plug.sign_in(conn, strategy)
  def plug(strategy, :verify, conn), do: Otp.Plug.verify(conn, strategy)

  @doc false
  @spec action(Otp.t(), Strategy.action(), map, keyword) ::
          :ok | {:ok, Ash.Resource.Record.t()} | {:ok, boolean} | {:error, any}
  def action(strategy, :request, params, options),
    do: Otp.Actions.request(strategy, params, options)

  def action(strategy, :sign_in, params, options),
    do: Otp.Actions.sign_in(strategy, params, options)

  def action(strategy, :verify, params, options),
    do: Otp.Actions.verify(strategy, params, options)

  @doc false
  @spec tokens_required?(Otp.t()) :: true
  def tokens_required?(_), do: true

  defp available_actions(strategy) do
    [:request]
    |> maybe_add(strategy.sign_in_enabled?, :sign_in)
    |> maybe_add(strategy.verify_enabled?, :verify)
  end

  defp maybe_add(list, true, item), do: list ++ [item]
  defp maybe_add(list, _false, _item), do: list
end
