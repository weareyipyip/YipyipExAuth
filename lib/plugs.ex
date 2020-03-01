defmodule YipyipExAuth.Plugs do
  @moduledoc """
  Function plugs to create and delete sessions. `&create_session/2` can be used in combination with
  `YipyipExAuth.Plugs.ProcessRefreshToken` for token refreshing.
  """
  alias Plug.Conn
  alias Phoenix.Token
  require Logger
  use YipyipExAuth.Utils.Constants
  alias YipyipExAuth.{Config, Utils}
  alias YipyipExAuth.Models.{Session, Tokens}

  @doc """
  Create or update a session. If a session exists in the conn, the session is updated, otherwise a new one is created.
  The session is put on the conn by `YipyipExAuth.Plugs.ProcessRefreshToken`.

  In both cases, new access / refresh tokens are created and stored in the conn's private map.
  The server-side session stored in the session store is created / updated as well.

  The tokens' signatures are split off and sent as cookies if the session's token signature
  transport mechanism is set to `:cookie`. By default, these are http-only strictly-same-site secure cookies.

  Optionally, it is possible to store extra payload in the access- and refresh tokens, which can be used to
  implement things like role-based authorization or forced logout after password change.
  """
  @spec create_session(Conn.t(), pos_integer | binary, Config.t(), any, any) :: Conn.t()
  def create_session(
        conn,
        user_id,
        %Config{
          refresh_token_ttl: max_refresh_ttl,
          session_store_module: session_store,
          session_ttl: session_ttl,
          access_token_ttl: max_access_ttl,
          access_token_salt: access_salt,
          refresh_token_salt: refresh_salt,
          access_token_key_digest: access_digest,
          refresh_token_key_digest: refresh_digest,
          access_cookie_name: access_cookie_name,
          refresh_cookie_name: refresh_cookie_name,
          access_cookie_opts: access_cookie_opts,
          refresh_cookie_opts: refresh_cookie_opts
        },
        extra_access_payload \\ nil,
        extra_refresh_payload \\ nil
      ) do
    now = System.system_time(:second)
    refresh_token_opts = [key_digest: refresh_digest, signed_at: now]
    access_token_opts = [key_digest: access_digest, signed_at: now]

    # the refresh token id is renewed every time so that refresh tokens are single-use only
    rtid = random_id()

    # update the existing session (as set by &refresh/2) or create a new one
    session = %{
      (Utils.get_session(conn) || new_session(conn, session_ttl, now, user_id))
      | refresh_token_id: rtid,
        refreshed_at: now,
        last_known_ip: conn.remote_ip |> :inet.ntoa() |> to_string()
    }

    # create access and refresh tokens and put them on the conn
    tst = session.token_signature_transport

    a_payload = %{
      uid: user_id,
      sid: session.id,
      tst: tst,
      exp: session.expires_at,
      epl: extra_access_payload
    }

    r_payload = %{
      id: rtid,
      uid: user_id,
      sid: session.id,
      tst: tst,
      exp: session.expires_at,
      epl: extra_refresh_payload
    }

    refresh_token = Token.sign(conn, refresh_salt, r_payload, refresh_token_opts)
    refresh_ttl = calc_ttl(session, now, max_refresh_ttl)
    access_token = Token.sign(conn, access_salt, a_payload, access_token_opts)
    access_ttl = calc_ttl(session, now, max_access_ttl)
    session_store.upsert(session, refresh_ttl)

    tokens = %Tokens{
      access_token: access_token,
      access_token_exp: now + access_ttl,
      refresh_token: refresh_token,
      refresh_token_exp: now + refresh_ttl
    }

    Logger.debug(fn ->
      operation = if session.created_at == now, do: "CREATED", else: "REFRESHED"
      "#{operation} session #{session.id}: #{inspect(session)}"
    end)

    conn
    |> transport_tokens(
      tst,
      tokens,
      access_ttl,
      refresh_ttl,
      access_cookie_opts,
      access_cookie_name,
      refresh_cookie_opts,
      refresh_cookie_name
    )
    |> Conn.put_private(@private_session_key, session)
    |> Conn.put_private(@private_access_token_payload_key, a_payload)
    |> Conn.put_private(@private_refresh_token_payload_key, r_payload)
  end

  @doc """
  Delete the persistent session identified by the session_id in the access token payload.

  Note that the access token remains valid until it expires, it is left up to the client to drop
  the access token. It will no longer be possible to refresh the session, however.
  """
  @spec delete_session(Conn.t(), Config.t()) :: Conn.t()
  def delete_session(conn, %Config{
        session_store_module: session_store,
        access_cookie_name: access_cookie_name,
        refresh_cookie_name: refresh_cookie_name,
        access_cookie_opts: access_cookie_opts,
        refresh_cookie_opts: refresh_cookie_opts
      }) do
    case conn.private[@private_access_token_payload_key] do
      %{sid: session_id, uid: user_id} -> session_store.delete(session_id, user_id)
      _ -> :ok
    end

    conn
    |> Conn.delete_resp_cookie(refresh_cookie_name, refresh_cookie_opts)
    |> Conn.delete_resp_cookie(access_cookie_name, access_cookie_opts)
  end

  ############
  # Privates #
  ############

  defp calc_ttl(session, now, max_ttl)
  defp calc_ttl(%{expires_at: nil}, _now, max_ttl), do: max_ttl
  defp calc_ttl(%{expires_at: timestamp}, now, max_ttl), do: min(timestamp - now, max_ttl)

  defp transport_tokens(conn, :bearer, tokens, _, _, _, _, _, _),
    do: Conn.put_private(conn, @private_tokens_key, tokens)

  defp transport_tokens(
         conn,
         :cookie,
         tokens,
         access_ttl,
         refresh_ttl,
         access_cookie_opts,
         access_cookie_name,
         refresh_cookie_opts,
         refresh_cookie_name
       ) do
    [at_header, at_payload, at_signature] = String.split(tokens.access_token, ".", parts: 3)
    access_token = at_header <> "." <> at_payload
    [rt_header, rt_payload, rt_signature] = String.split(tokens.refresh_token, ".", parts: 3)
    refresh_token = rt_header <> "." <> rt_payload
    tokens = %{tokens | access_token: access_token, refresh_token: refresh_token}

    access_cookie_opts = Keyword.put(access_cookie_opts, :max_age, access_ttl)
    refresh_cookie_opts = Keyword.put(refresh_cookie_opts, :max_age, refresh_ttl)

    conn
    |> Conn.put_private(@private_tokens_key, tokens)
    |> Conn.put_resp_cookie(access_cookie_name, "." <> at_signature, access_cookie_opts)
    |> Conn.put_resp_cookie(refresh_cookie_name, "." <> rt_signature, refresh_cookie_opts)
  end

  defp new_session(conn, session_ttl, timestamp, user_id) do
    %Session{
      created_at: timestamp,
      id: random_id(),
      user_id: user_id,
      token_signature_transport: Map.fetch!(conn.private, @private_token_signature_transport_key),
      expires_at:
        case session_ttl do
          ttl when is_integer(ttl) -> ttl + timestamp
          _ -> nil
        end
    }
  end

  # generate random IDs of a specified bit length, default 128, as hex string
  # 2^128 == 16^32 so 128 bits of randomness is equal to a UUID (actually slightly more)
  defp random_id(bits \\ 128),
    do: bits |> div(8) |> :crypto.strong_rand_bytes() |> Base.encode16()
end
