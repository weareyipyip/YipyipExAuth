defmodule YipyipExAuth.Plugs.ProcessAccessToken do
  @moduledoc """
  Plug to process and verify access tokens. Must be initialized with a `YipyipExAuth.Config`-struct, which can be initialized itself using `YipyipExAuth.Config.from_enum/1`.

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

    pipeline :valid_access_token do
      plug YipyipExAuth.Plugs.ProcessAccessToken, @config
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
      alias YipyipExAuth.Plugs.ProcessAccessToken
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
      @plug_opts ProcessAccessToken.init(@config)

      # "reject" requests without bearer token
      iex> conn = %Conn{} |> ProcessAccessToken.call(@plug_opts)
      iex> "bearer token not found" = Utils.get_auth_error(conn)
      iex> conn.assigns
      %{}

      # "reject" requests with invalid token
      iex> config = %{@config | access_token_salt: "different"}
      iex> conn = build_conn() |> put_access_token(config) |> ProcessAccessToken.call(@plug_opts)
      iex> "bearer token invalid" = Utils.get_auth_error(conn)
      iex> conn.assigns
      %{}

      # "reject" requests with expired bearer token
      iex> plug_opts = ProcessAccessToken.init(%{@config | access_token_ttl: -1})
      iex> conn = build_conn() |> put_access_token(@config) |> ProcessAccessToken.call(plug_opts)
      iex> "bearer token expired" = Utils.get_auth_error(conn)
      iex> conn.assigns
      %{}

      # "reject" requests where the signature transport mechanism does not match the session's initial value
      iex> token = generate_access_token(build_conn(), @config, %{tst: :cookie})
      iex> conn = build_conn() |> put_access_token(@config, token) |> ProcessAccessToken.call(@plug_opts)
      iex> "token signature transport invalid" = Utils.get_auth_error(conn)
      iex> conn.assigns
      %{}

      # "reject" requests with an expired session
      iex> token = generate_access_token(build_conn(), @config, %{exp: 1})
      iex> conn = build_conn() |> put_access_token(@config, token) |> ProcessAccessToken.call(@plug_opts)
      iex> "session expired" = Utils.get_auth_error(conn)
      iex> conn.assigns
      %{}

      # "allow" requests with valid bearer token
      iex> conn = build_conn() |> put_access_token(@config) |> ProcessAccessToken.call(@plug_opts)
      iex> nil = Utils.get_auth_error(conn)
      iex> conn.assigns
      %{current_session_id: "a", current_user_id: 1, extra_access_token_payload: %{}}

      # "allow" requests with valid bearer token with signature in cookie
      iex> token = generate_access_token(build_conn(), @config, %{tst: :cookie})
      iex> [header, encoded_payload, signature] = String.split(token, ".", parts: 3)
      iex> conn = build_conn()
      ...> |> put_access_token(@config, header <> "." <> encoded_payload)
      ...> |> Plug.Test.put_req_cookie(@config.access_cookie_name, "." <> signature)
      ...> |> ProcessAccessToken.call(@plug_opts)
      iex> nil = Utils.get_auth_error(conn)
      iex> conn.assigns
      %{current_session_id: "a", current_user_id: 1, extra_access_token_payload: %{}}
  """
  @behaviour Plug
  alias Phoenix.Token
  alias Plug.Conn
  use YipyipExAuth.Utils.Constants
  alias YipyipExAuth.{SharedInternals, Config}
  require Logger

  @doc false
  @impl true
  @spec init(YipyipExAuth.Config.t()) :: Plug.opts()
  def init(%Config{
        access_cookie_name: cookie_name,
        access_token_salt: salt,
        access_token_ttl: max_age,
        access_token_key_digest: digest,
        session_store_module: session_store
      }) do
    {session_store, salt, cookie_name, key_digest: digest, max_age: max_age}
  end

  @doc false
  @impl true
  @spec call(Conn.t(), Plug.opts()) :: Conn.t()
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
