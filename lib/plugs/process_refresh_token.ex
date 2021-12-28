defmodule YipyipExAuth.Plugs.ProcessRefreshToken do
  @moduledoc """
  Plug to process and verify refresh tokens. Must be initialized with a `YipyipExAuth.Config`-struct, which can be initialized itself using `YipyipExAuth.Config.from_enum/1`.

  The token signature source (bearer or cookie) must match the `token_signature_transport` specified in the token payload.

  A refresh token can only be used to refresh a session once. A single refresh token id is stored in the
  server-side session by `YipyipExAuth.Plugs.upsert_session/3` to enforce this.

  The plug does not reject unauthenticated requests by itself. If a request is successfully verified, the user ID, session ID and extra payload are assigned to the conn. If not, an authentication error message is put in the conn's private map, which can be retrieved using `YipyipExAuth.Utils.get_auth_error/1`. This allows applications to implement their own plug to reject unauthenticated requests, for example:

  ## Usage example that rejects unauthenticated requests
  ```
  defmodule MyPhoenixAppWeb.Router do
    use MyPhoenixAppWeb, :router

    @config YipyipExAuth.Config.from_enum(
                             session_ttl: 68400,
                             refresh_token_ttl: 3600,
                             session_store_module: MyModule
                           )

    pipeline :valid_refresh_token do
      plug YipyipExAuth.Plugs.ProcessRefreshToken, @config
      plug :only_authenticated
    end

    @doc \"\"\"
    Reject unauthenticated requests
    \"\"\"
    def only_authenticated(%{assigns: %{current_user_id: _}} = conn, _opts), do: conn

    def only_authenticated(conn, _opts) do
      auth_error = YipyipExAuth.Utils.get_auth_error(conn)
      conn |> Plug.Conn.send_resp(401, auth_error) |> halt()
    end
  end
  ```

  In this way, applications can completely customize how to respond to unauthenticated requests and how much information to expose to the client.

  ## Examples / doctests

      alias Plug.Conn
      alias YipyipExAuth.Plugs.ProcessRefreshToken
      alias YipyipExAuth.Utils
      import YipyipExAuth.TestHelpers

      # only available when Mix env = test
      alias YipyipExAuth.TestSupport.FakeSessionStore
      import YipyipExAuth.TestSupport.Shared

      @config YipyipExAuth.Config.from_enum(
                              session_ttl: 68400,
                              refresh_token_ttl: 3600,
                              session_store_module: FakeSessionStore
                            )
      @plug_opts ProcessRefreshToken.init(@config)

      # "reject" requests without refresh token
      iex> conn = %Conn{} |> ProcessRefreshToken.call(@plug_opts)
      iex> "refresh token not found" = Utils.get_auth_error(conn)
      iex> {conn.assigns, Utils.get_session(conn)}
      {%{}, nil}

      # "reject" requests with invalid token
      iex> config = %{@config | refresh_token_salt: "different"}
      iex> conn = build_conn() |> put_refresh_token(config) |> ProcessRefreshToken.call(@plug_opts)
      iex> "refresh token invalid" = Utils.get_auth_error(conn)
      iex> {conn.assigns, Utils.get_session(conn)}
      {%{}, nil}

      # "reject" requests with expired refresh token
      iex> plug_opts = ProcessRefreshToken.init(%{@config | refresh_token_ttl: -1})
      iex> conn = build_conn() |> put_refresh_token(@config) |> ProcessRefreshToken.call(plug_opts)
      iex> "refresh token expired" = Utils.get_auth_error(conn)
      iex> {conn.assigns, Utils.get_session(conn)}
      {%{}, nil}

      # "reject" requests where the signature transport mechanism does not match the session's initial value
      iex> token = generate_refresh_token(build_conn(), @config, %{tst: :cookie})
      iex> conn = build_conn() |> put_refresh_token(@config, token) |> ProcessRefreshToken.call(@plug_opts)
      iex> "token signature transport invalid" = Utils.get_auth_error(conn)
      iex> {conn.assigns, Utils.get_session(conn)}
      {%{}, nil}

      # "reject" requests with an expired session
      iex> token = generate_refresh_token(build_conn(), @config, %{exp: 1})
      iex> conn = build_conn() |> put_refresh_token(@config, token) |> ProcessRefreshToken.call(@plug_opts)
      iex> "session expired" = Utils.get_auth_error(conn)
      iex> {conn.assigns, Utils.get_session(conn)}
      {%{}, nil}

      # "allow" requests with valid refresh token
      iex> conn = build_conn() |> put_refresh_token(@config) |> ProcessRefreshToken.call(@plug_opts)
      iex> nil = Utils.get_auth_error(conn)
      iex> conn.assigns
      %{current_session_id: "a", current_user_id: 1, extra_refresh_token_payload: %{}}
      iex> %YipyipExAuth.Models.Session{} = Utils.get_session(conn)

      # "allow" requests with valid refresh token with signature in cookie
      iex> token = generate_refresh_token(build_conn(), @config, %{tst: :cookie})
      iex> [header, encoded_payload, signature] = String.split(token, ".", parts: 3)
      iex> conn = build_conn()
      ...> |> put_refresh_token(@config, header <> "." <> encoded_payload)
      ...> |> Plug.Test.put_req_cookie(@config.refresh_cookie_name, "." <> signature)
      ...> |> ProcessRefreshToken.call(@plug_opts)
      iex> nil = Utils.get_auth_error(conn)
      iex> conn.assigns
      %{current_session_id: "a", current_user_id: 1, extra_refresh_token_payload: %{}}
      iex> %YipyipExAuth.Models.Session{} = Utils.get_session(conn)
  """
  @behaviour Plug
  alias Phoenix.Token
  alias Plug.Conn
  use YipyipExAuth.Utils.Constants
  alias YipyipExAuth.{Config, SharedInternals}
  alias YipyipExAuth.Models.Session
  require Logger

  @doc false
  @impl true
  @spec init(YipyipExAuth.Config.t()) :: Plug.opts()
  def init(%Config{
        refresh_cookie_name: cookie_name,
        refresh_token_salt: salt,
        refresh_token_ttl: max_age,
        refresh_token_key_digest: digest,
        session_store_module: session_store
      }) do
    {session_store, salt, cookie_name, key_digest: digest, max_age: max_age}
  end

  @doc false
  @impl true
  @spec call(Conn.t(), Plug.opts()) :: Conn.t()
  def call(conn, {session_store, salt, cookie_name, verification_opts}) do
    with {:token, {sig_transport, token}} <- SharedInternals.get_token(conn, cookie_name),
         {:ok, payload} <- Token.verify(conn, salt, token, verification_opts),
         {:pl, %{uid: uid, sid: sid, id: rtid, tst: tst, exp: exp, epl: epl}} <- {:pl, payload},
         {:transport_matches, true} <- {:transport_matches, sig_transport == tst},
         {:session_expired, false} <-
           SharedInternals.session_expired?(sid, uid, exp, session_store),
         {:session, %Session{user_id: ^uid} = session} <- {:session, session_store.get(sid, uid)},
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

      {:pl, _} ->
        SharedInternals.auth_error(conn, "invalid refresh token payload")

      {:transport_matches, false} ->
        SharedInternals.auth_error(conn, "token signature transport invalid")

      {:session, nil} ->
        SharedInternals.auth_error(conn, "session not found")

      {:session, %Session{}} ->
        SharedInternals.auth_error(conn, "session user mismatch")

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
