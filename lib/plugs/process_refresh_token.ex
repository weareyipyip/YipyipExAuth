defmodule YipyipExAuth.Plugs.ProcessRefreshToken do
  @moduledoc """
  Process refresh tokens.

  The token signature source (bearer or cookie) must match
  the `token_signature_transport` specified in the token payload.

  A refresh token can only be used to refresh a session once. A single refresh token id is stored in the
  server-side session by `create/2` to enforce this.
  """
  @behaviour Plug
  alias Phoenix.Token
  alias Plug.Conn
  use YipyipExAuth.Utils.Constants
  alias YipyipExAuth.{Config, SharedInternals}
  alias YipyipExAuth.Models.Session
  require Logger

  @impl true
  def init(%Config{
        refresh_cookie_name: cookie_name,
        refresh_token_salt: salt,
        refresh_token_ttl: max_age,
        refresh_token_key_digest: digest,
        session_store_module: session_store
      }) do
    {session_store, salt, cookie_name, key_digest: digest, max_age: max_age}
  end

  @impl true
  def call(conn, {session_store, salt, cookie_name, verification_opts}) do
    with {:token, {sig_transport, token}} <-
           {:token, SharedInternals.get_token(conn, cookie_name)},
         {:ok, %{uid: uid, sid: sid, id: rtid, tst: tst, exp: exp, epl: epl} = payload} <-
           Token.verify(conn, salt, token, verification_opts),
         {:transport_matches, true} <- {:transport_matches, sig_transport == tst},
         {:session_expired, false} <-
           SharedInternals.session_expired?(sid, uid, exp, session_store),
         {:session, %Session{user_id: ^uid} = session} <-
           {:session, session_store.get(sid, uid)},
         {:token_fresh, true} <- {:token_fresh, session.refresh_token_id == rtid} do
      conn
      |> Conn.assign(:current_user_id, uid)
      |> Conn.assign(:current_session_id, sid)
      |> Conn.assign(:extra_refresh_token_payload, epl)
      |> Conn.put_private(@private_session_key, session)
      |> Conn.put_private(@private_refresh_token_payload_key, payload)
      |> Conn.put_private(@private_token_signature_transport_key, tst)
    else
      {:token, nil} ->
        SharedInternals.auth_error(conn, "refresh token not found")

      {:error, :expired} ->
        SharedInternals.auth_error(conn, "refresh token expired")

      {:error, :invalid} ->
        SharedInternals.auth_error(conn, "refresh token invalid")

      {:ok, _} ->
        SharedInternals.auth_error(conn, "invalid refresh token payload")

      {:transport_matches, false} ->
        SharedInternals.auth_error(conn, "token signature transport invalid")

      {:session, :not_found} ->
        SharedInternals.auth_error(conn, "session not found")

      {:session_expired, true} ->
        SharedInternals.auth_error(conn, "session expired")

      {:token_fresh, false} ->
        SharedInternals.auth_error(conn, "refresh token stale")

      error ->
        Logger.error("Unexpected auth error: #{inspect(error)}")
        SharedInternals.auth_error(conn, "unexpected error")
    end
  end
end
