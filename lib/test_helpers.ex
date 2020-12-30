defmodule YipyipExAuth.TestHelpers do
  @moduledoc """
  Helper functions for generating "valid" tokens for testing purposes.

  WARNING: These functions should not be called outside of tests.
  """
  alias YipyipExAuth.Config
  @default_access_payload %{uid: 1, sid: "a", tst: :bearer, exp: nil, epl: %{}}
  @default_refresh_payload %{uid: 1, sid: "a", id: "a", tst: :bearer, exp: nil, epl: %{}}
  alias YipyipExAuth.SharedInternals

  @doc """
  Sets request header "authorization" to "Bearer `access_token`".
  """
  @spec put_access_token(Plug.Conn.t(), Config.t(), binary | nil) :: Plug.Conn.t()
  def put_access_token(conn, config, token \\ nil) do
    token = token || generate_access_token(conn, config)
    Plug.Conn.put_req_header(conn, "authorization", "Bearer #{token}")
  end

  @doc """
  Sets request header "authorization" to "Bearer `refresh_token`".
  """
  @spec put_refresh_token(Plug.Conn.t(), Config.t(), binary | nil) :: Plug.Conn.t()
  def put_refresh_token(conn, config, token \\ nil) do
    token = token || generate_refresh_token(conn, config)
    Plug.Conn.put_req_header(conn, "authorization", "Bearer #{token}")
  end

  @doc """
  Generate an access token. Default payload can be overridden. The default payload is:

      #{inspect(@default_access_payload)}
  """
  @spec generate_access_token(binary | module | Plug.Conn.t(), Config.t(), map) :: binary
  def generate_access_token(
        token_context,
        config,
        payload_overrides \\ %{}
      ) do
    Phoenix.Token.sign(
      token_context,
      config.access_token_salt,
      @default_access_payload
      |> Map.merge(payload_overrides)
      |> SharedInternals.compress_access_payload(),
      key_digest: config.access_token_key_digest
    )
  end

  @doc """
  Generate a refresh token. Default payload can be overridden. The default payload is:

      #{inspect(@default_refresh_payload)}
  """
  @spec generate_refresh_token(binary | module | Plug.Conn.t(), Config.t(), map) :: binary
  def generate_refresh_token(
        token_context,
        config,
        payload_overrides \\ %{}
      ) do
    Phoenix.Token.sign(
      token_context,
      config.refresh_token_salt,
      @default_refresh_payload
      |> Map.merge(payload_overrides)
      |> SharedInternals.compress_refresh_payload(),
      key_digest: config.refresh_token_key_digest
    )
  end
end
