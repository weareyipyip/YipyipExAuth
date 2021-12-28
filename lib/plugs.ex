defmodule YipyipExAuth.Plugs do
  @moduledoc """
  Function plugs to create and delete sessions. `upsert_session/3` can be used in combination with `YipyipExAuth.Plugs.ProcessRefreshToken` for token refreshing.
  """
  alias Plug.Conn
  alias Phoenix.Token
  require Logger
  use YipyipExAuth.Utils.Constants
  alias YipyipExAuth.{Config, Utils}
  alias YipyipExAuth.Models.{Session, Tokens}

  @type upsert_session_opts :: [
          extra_access_payload: keyword() | map() | nil,
          extra_refresh_payload: keyword() | map() | nil,
          extra_session_payload: keyword() | map() | nil
        ]

  @doc """
  Create or update a session. If a session exists in the conn, the session is updated, otherwise a new one is created.
  The session is put on the conn by `YipyipExAuth.Plugs.ProcessRefreshToken`.

  In both cases, new access / refresh tokens are created and stored in the conn's private map.
  The server-side session stored in the session store is created / updated as well.

  If a new session is created, this plug must be preceded by `YipyipExAuth.Utils.set_token_signature_transport/2` and `YipyipExAuth.Utils.set_user_id/2` or an error will be raised.

  The tokens' signatures are split off and sent as cookies if the session's token signature transport mechanism is set to `:cookie`. By default, these are http-only strictly-same-site secure cookies.

  Optionally, it is possible to store extra payload in the access- and refresh tokens, which can be used to implement things like role-based authorization or forced logout after password change.

  Raises on session store errors. No recovery is possible from this error - the session HAS to be stored or there is no point in handing out tokens.

  ## Examples / doctests

      use YipyipExAuth.Utils.Constants
      alias Plug.Conn
      alias YipyipExAuth.Utils
      alias YipyipExAuth.Models.{Session, Tokens}
      import YipyipExAuth.Plugs

      # only available when Mix env = test
      alias YipyipExAuth.TestSupport.FakeSessionStore
      import YipyipExAuth.TestSupport.Shared

      @config YipyipExAuth.Config.from_enum(
                session_ttl: 68400,
                refresh_token_ttl: 3600,
                session_store_module: FakeSessionStore
              )


      # error if user id not set for new session
      iex> %Conn{} |> Utils.set_token_signature_transport(:bearer) |> upsert_session(@config)
      ** (RuntimeError) Set user id using Utils.set_user_id/2

      # error if signature transport not set for new session
      iex> %Conn{} |> Utils.set_user_id(1) |> upsert_session(@config)
      ** (RuntimeError) Set token signature transport using Utils.set_token_signature_transport/2

      # creates session if none present in conn
      iex> conn = build_conn()
      ...> |> Utils.set_user_id(1)
      ...> |> Utils.set_token_signature_transport(:cookie)
      ...> |> upsert_session(@config)
      iex> %Session{} = Utils.get_session(conn)
      iex> %Tokens{} = Utils.get_tokens(conn)

      # renews session if present in conn, updating only refresh_token_id, refreshed_at and last_known_ip
      # existing session's user id or signature transport will not change despite attempted override
      iex> old_session = %Session{token_signature_transport: :bearer, user_id: 43}
      iex> conn = build_conn()
      ...> |> Conn.put_private(@private_session_key, old_session)
      ...> |> Utils.set_token_signature_transport(:cookie)
      ...> |> Utils.set_user_id(1)
      ...> |> upsert_session(@config)
      iex> session = Utils.get_session(conn) |> Map.from_struct()
      iex> old_session = Map.from_struct(old_session)
      iex> Enum.map(~w(id user_id created_at expires_at token_signature_transport)a, & session[&1] == old_session[&1])
      [true, true, true, true, true]
      iex> Enum.map(~w(refresh_token_id refreshed_at last_known_ip)a, & session[&1] == old_session[&1])
      [false, false, false]

      # returns signatures in cookies if requested, which removes signatures from tokens
      iex> conn = build_conn()
      ...> |> Utils.set_token_signature_transport(:cookie)
      ...> |> Utils.set_user_id(1)
      ...> |> upsert_session(@config)
      iex> cookies = conn |> Conn.fetch_cookies() |> Map.get(:cookies)
      iex> <<_access_sig::binary>> = Map.get(cookies, @config.access_cookie_name)
      iex> <<_refresh_sig::binary>> = Map.get(cookies, @config.refresh_cookie_name)
      iex> true = Regex.match?(~r/\\w\\.\\w/,  conn |> Utils.get_tokens() |> Map.get(:access_token))
      iex> true = Regex.match?(~r/\\w\\.\\w/,  conn |> Utils.get_tokens() |> Map.get(:refresh_token))

      # allows adding extra payload to tokens
      iex> conn = build_conn()
      ...> |> Utils.set_token_signature_transport(:bearer)
      ...> |> Utils.set_user_id(1)
      ...> |> upsert_session(@config, extra_access_payload: %{much: :extra}, extra_refresh_payload: %{really: true})
      iex> %{epl: %{much: :extra}} = Utils.get_access_token_payload(conn)
      iex> %{epl: %{really: true}} = Utils.get_refresh_token_payload(conn)

      # allows adding extra payload to session
      iex> conn = build_conn()
      ...> |> Utils.set_user_id(1)
      ...> |> Utils.set_token_signature_transport(:cookie)
      ...> |> upsert_session(@config, extra_session_payload: %{what?: "that's right!"})
      iex> %Session{extra_payload: %{what?: "that's right!"}} = Utils.get_session(conn)
  """
  @spec upsert_session(Conn.t(), Config.t(), upsert_session_opts()) :: Conn.t()
  def upsert_session(
        conn,
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
        opts \\ []
      ) do
    now = System.system_time(:second)
    extra_access_payload = Map.new(opts[:extra_access_payload] || %{})
    extra_refresh_payload = Map.new(opts[:extra_refresh_payload] || %{})
    extra_session_payload = Map.new(opts[:extra_session_payload] || %{})
    refresh_token_opts = [key_digest: refresh_digest, signed_at: now]
    access_token_opts = [key_digest: access_digest, signed_at: now]

    # the refresh token id is renewed every time so that refresh tokens are single-use only
    refresh_token_id = random_id()

    # update the existing session or create a new one
    session = %{
      Session.upgrade_old_session(Utils.get_session(conn) || new_session(conn, session_ttl, now))
      | refresh_token_id: refresh_token_id,
        refreshed_at: now,
        last_known_ip: conn.remote_ip |> :inet.ntoa() |> to_string(),
        extra_payload: extra_session_payload
    }

    Logger.debug(fn ->
      operation = if session.created_at == now, do: "CREATED", else: "REFRESHED"
      "#{operation} session #{session.id}: #{inspect(session)}"
    end)

    # create access and refresh tokens and put them on the conn
    token_signature_transport = session.token_signature_transport
    user_id = session.user_id

    a_payload = %{
      uid: user_id,
      sid: session.id,
      tst: token_signature_transport,
      exp: session.expires_at,
      epl: extra_access_payload
    }

    r_payload = %{
      id: refresh_token_id,
      uid: user_id,
      sid: session.id,
      tst: token_signature_transport,
      exp: session.expires_at,
      epl: extra_refresh_payload
    }

    refresh_token = Token.sign(conn, refresh_salt, r_payload, refresh_token_opts)
    refresh_ttl = calc_ttl(session, now, max_refresh_ttl)
    access_token = Token.sign(conn, access_salt, a_payload, access_token_opts)
    access_ttl = calc_ttl(session, now, max_access_ttl)

    tokens = %Tokens{
      access_token: access_token,
      access_token_exp: now + access_ttl,
      refresh_token: refresh_token,
      refresh_token_exp: now + refresh_ttl
    }

    # store the session
    case session_store.upsert(session, refresh_ttl) do
      :ok ->
        :ok

      error ->
        error |> inspect() |> Logger.error()
        raise(RuntimeError, "session could not be stored")
    end

    # dress up the conn and return
    conn
    |> transport_tokens(
      token_signature_transport,
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
  Create or update a session. If a session exists in the conn, the session is updated, otherwise a new one is created.
  The session is put on the conn by `YipyipExAuth.Plugs.ProcessRefreshToken`.

  In both cases, new access / refresh tokens are created and stored in the conn's private map.
  The server-side session stored in the session store is created / updated as well.

  If a new session is created, this plug must be preceded by `YipyipExAuth.Utils.set_token_signature_transport/2` and `YipyipExAuth.Utils.set_user_id/2` or an error will be raised.

  The tokens' signatures are split off and sent as cookies if the session's token signature transport mechanism is set to `:cookie`. By default, these are http-only strictly-same-site secure cookies.

  Optionally, it is possible to store extra payload in the access- and refresh tokens, which can be used to implement things like role-based authorization or forced logout after password change.

  Raises on session store errors. No recovery is possible from this error - the session HAS to be stored or there is no point in handing out tokens.

  ## Examples / doctests

      use YipyipExAuth.Utils.Constants
      alias Plug.Conn
      alias YipyipExAuth.Utils
      alias YipyipExAuth.Models.{Session, Tokens}
      import YipyipExAuth.Plugs

      # only available when Mix env = test
      alias YipyipExAuth.TestSupport.FakeSessionStore
      import YipyipExAuth.TestSupport.Shared

      @config YipyipExAuth.Config.from_enum(
                session_ttl: 68400,
                refresh_token_ttl: 3600,
                session_store_module: FakeSessionStore
              )


      # error if user id not set for new session
      iex> %Conn{} |> Utils.set_token_signature_transport(:bearer) |> create_session(@config)
      ** (RuntimeError) Set user id using Utils.set_user_id/2

      # error if signature transport not set for new session
      iex> %Conn{} |> Utils.set_user_id(1) |> create_session(@config)
      ** (RuntimeError) Set token signature transport using Utils.set_token_signature_transport/2

      # creates session if none present in conn
      iex> conn = build_conn()
      ...> |> Utils.set_user_id(1)
      ...> |> Utils.set_token_signature_transport(:cookie)
      ...> |> create_session(@config)
      iex> %Session{} = Utils.get_session(conn)
      iex> %Tokens{} = Utils.get_tokens(conn)

      # renews session if present in conn, updating only refresh_token_id, refreshed_at and last_known_ip
      # existing session's user id or signature transport will not change despite attempted override
      iex> old_session = %Session{token_signature_transport: :bearer, user_id: 43}
      iex> conn = build_conn()
      ...> |> Conn.put_private(@private_session_key, old_session)
      ...> |> Utils.set_token_signature_transport(:cookie)
      ...> |> Utils.set_user_id(1)
      ...> |> create_session(@config)
      iex> session = Utils.get_session(conn) |> Map.from_struct()
      iex> old_session = Map.from_struct(old_session)
      iex> Enum.map(~w(id user_id created_at expires_at token_signature_transport)a, & session[&1] == old_session[&1])
      [true, true, true, true, true]
      iex> Enum.map(~w(refresh_token_id refreshed_at last_known_ip)a, & session[&1] == old_session[&1])
      [false, false, false]

      # returns signatures in cookies if requested, which removes signatures from tokens
      iex> conn = build_conn()
      ...> |> Utils.set_token_signature_transport(:cookie)
      ...> |> Utils.set_user_id(1)
      ...> |> create_session(@config)
      iex> cookies = conn |> Conn.fetch_cookies() |> Map.get(:cookies)
      iex> <<_access_sig::binary>> = Map.get(cookies, @config.access_cookie_name)
      iex> <<_refresh_sig::binary>> = Map.get(cookies, @config.refresh_cookie_name)
      iex> true = Regex.match?(~r/\\w\\.\\w/,  conn |> Utils.get_tokens() |> Map.get(:access_token))
      iex> true = Regex.match?(~r/\\w\\.\\w/,  conn |> Utils.get_tokens() |> Map.get(:refresh_token))

      # allows adding extra payload to tokens
      iex> conn = build_conn()
      ...> |> Utils.set_token_signature_transport(:bearer)
      ...> |> Utils.set_user_id(1)
      ...> |> create_session(@config, %{much: :extra}, %{really: true})
      iex> %{epl: %{much: :extra}} = Utils.get_access_token_payload(conn)
      iex> %{epl: %{really: true}} = Utils.get_refresh_token_payload(conn)
  """
  @deprecated "Use YipyipExAuth.Plugs.upsert_session/3."
  @spec create_session(Plug.Conn.t(), YipyipExAuth.Config.t(), any, any) :: Plug.Conn.t()
  def create_session(conn, config, extra_access_payload \\ nil, extra_refresh_payload \\ nil) do
    upsert_session(conn, config,
      extra_access_payload: extra_access_payload,
      extra_refresh_payload: extra_refresh_payload
    )
  end

  @doc """
  Delete the persistent session identified by the session_id in the access token payload.

  Note that the access token remains valid until it expires, it is left up to the client to drop the access token. It will no longer be possible to refresh the session, however.

  ## Examples / doctests

      # instructs browsers to clear signature cookies
      iex> build_conn()
      ...> |> Plug.Test.put_req_cookie(@config.access_cookie_name, "anything")
      ...> |> Plug.Test.put_req_cookie(@config.refresh_cookie_name, "anything")
      ...> |> delete_session(@config)
      ...> |> Conn.fetch_cookies()
      ...> |> Map.get(:cookies)
      %{}
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

  defp new_session(conn, session_ttl, timestamp) do
    %Session{
      created_at: timestamp,
      id: random_id(),
      user_id: get_user_id!(conn),
      token_signature_transport: get_sig_transport!(conn),
      expires_at:
        case session_ttl do
          ttl when is_integer(ttl) -> ttl + timestamp
          _ -> nil
        end
    }
  end

  defp get_user_id!(conn) do
    conn
    |> Utils.get_user_id()
    |> case do
      nil -> raise "Set user id using Utils.set_user_id/2"
      result -> result
    end
  end

  defp get_sig_transport!(conn) do
    conn
    |> Utils.get_token_signature_transport()
    |> case do
      nil -> raise "Set token signature transport using Utils.set_token_signature_transport/2"
      result -> result
    end
  end

  # generate random IDs of a specified bit length, default 128, as hex string
  # 2^128 == 16^32 so 128 bits of randomness is equal to a UUID (actually slightly more)
  defp random_id(bits \\ 128) do
    bits |> div(8) |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)
  end
end
