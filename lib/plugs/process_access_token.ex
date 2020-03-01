defmodule YipyipExAuth.Plugs.ProcessAccessToken do
  @moduledoc """
  Plug to process access tokens.
  """
  @behaviour Plug
  alias Phoenix.Token
  alias Plug.Conn
  use YipyipExAuth.Utils.Constants
  alias YipyipExAuth.{SharedInternals, Config}
  require Logger

  @impl true
  def init(%Config{
        access_cookie_name: cookie_name,
        access_token_salt: salt,
        access_token_ttl: max_age,
        access_token_key_digest: digest,
        session_store_module: session_store
      }) do
    {session_store, salt, cookie_name, key_digest: digest, max_age: max_age}
  end

  @impl true
  def call(conn, {session_store, salt, cookie_name, verification_opts}) do
    with {sig_transport, token} <- SharedInternals.get_token(conn, cookie_name),
         {:ok, payload} <- Token.verify(conn, salt, token, verification_opts),
         %{uid: user_id, tst: exp_sig_trans, sid: session_id, exp: expires_at, epl: epl} <-
           payload,
         {:transport_matches, true} <- {:transport_matches, sig_transport == exp_sig_trans},
         {:session_expired, false} <-
           SharedInternals.session_expired?(session_id, user_id, expires_at, session_store) do
      conn
      |> Conn.assign(:current_user_id, user_id)
      |> Conn.assign(:current_session_id, session_id)
      |> Conn.assign(:extra_access_token_payload, epl)
      |> Conn.put_private(@private_access_token_payload_key, payload)
      |> Conn.put_private(@private_token_signature_transport_key, sig_transport)
    else
      nil ->
        SharedInternals.auth_error(conn, "bearer token not found")

      {:error, :expired} ->
        SharedInternals.auth_error(conn, "bearer token expired")

      {:error, :invalid} ->
        SharedInternals.auth_error(conn, "bearer token invalid")

      {:ok, _} ->
        SharedInternals.auth_error(conn, "invalid bearer token payload")

      {:transport_matches, false} ->
        SharedInternals.auth_error(conn, "token signature transport invalid")

      {:session_expired, true} ->
        SharedInternals.auth_error(conn, "session expired")

      error ->
        Logger.error("Unexpected auth error: #{inspect(error)}")
        SharedInternals.auth_error(conn, "unexpected error")
    end
  end
end
