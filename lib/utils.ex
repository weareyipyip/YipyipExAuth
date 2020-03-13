defmodule YipyipExAuth.Utils.Constants do
  @moduledoc false
  defmacro __using__(_opts) do
    quote do
      @private_session_key :yy_session_session
      @private_tokens_key :yy_session_tokens
      @private_access_token_payload_key :yy_session_access_token_payload
      @private_refresh_token_payload_key :yy_session_refresh_token_payload
      @private_auth_error_key :yy_session_auth_error
      @private_token_signature_transport_key :yy_session_token_signature_transport
      @private_user_id_key :yy_session_user_id
    end
  end
end

defmodule YipyipExAuth.Utils do
  @moduledoc """
  Utility functions, mainly getters and setters for module internals.
  """
  use YipyipExAuth.Utils.Constants
  alias Plug.Conn
  alias YipyipExAuth.Models.{Session, Tokens}

  @doc """
  Get current session, if present.
  """
  @spec get_session(Conn.t()) :: Session.t() | nil
  def get_session(conn), do: Map.get(conn.private, @private_session_key)

  @doc """
  Get tokens, if present.
  """
  @spec get_tokens(Conn.t()) :: Tokens.t() | nil
  def get_tokens(conn), do: Map.get(conn.private, @private_tokens_key)

  @doc """
  Get access token payload, if present.
  """
  @spec get_access_token_payload(Conn.t()) :: map() | nil
  def get_access_token_payload(conn), do: Map.get(conn.private, @private_access_token_payload_key)

  @doc """
  Get refresh token payload, if present.
  """
  @spec get_refresh_token_payload(Conn.t()) :: map() | nil
  def get_refresh_token_payload(conn),
    do: Map.get(conn.private, @private_refresh_token_payload_key)

  @doc """
  Get auth error, if present.
  """
  @spec get_auth_error(Conn.t()) :: binary() | nil
  def get_auth_error(conn), do: Map.get(conn.private, @private_auth_error_key)

  @doc """
  Get token signature transport mechanism, if present.
  """
  @spec get_token_signature_transport(Conn.t()) :: atom() | nil
  def get_token_signature_transport(conn),
    do: Map.get(conn.private, @private_token_signature_transport_key)

  @doc """
  Get user id for session creation, if present.
  """
  @spec get_user_id(Conn.t()) :: any()
  def get_user_id(conn), do: Map.get(conn.private, @private_user_id_key)

  @doc """
  Set token signature transport mechanism. Must be one of
  `"bearer"`, `"cookie"`, `:bearer` or `:cookie`.

  ## Examples / doctests

      iex> :bearer = %Conn{} |> set_token_signature_transport("bearer") |> get_token_signature_transport()
      iex> :bearer = %Conn{} |> set_token_signature_transport(:bearer) |> get_token_signature_transport()
      iex> :cookie = %Conn{} |> set_token_signature_transport("cookie") |> get_token_signature_transport()
      iex> :cookie = %Conn{} |> set_token_signature_transport(:cookie) |> get_token_signature_transport()

      iex> set_token_signature_transport(%Conn{}, "anything else")
      ** (FunctionClauseError) no function clause matching in YipyipExAuth.Utils.set_token_signature_transport/2
  """
  @spec set_token_signature_transport(Conn.t(), binary() | :bearer | :cookie) :: Conn.t()
  def set_token_signature_transport(conn, token_signature_transport)
  def set_token_signature_transport(conn, "bearer"), do: set_tst(conn, :bearer)
  def set_token_signature_transport(conn, "cookie"), do: set_tst(conn, :cookie)
  def set_token_signature_transport(conn, :bearer), do: set_tst(conn, :bearer)
  def set_token_signature_transport(conn, :cookie), do: set_tst(conn, :cookie)

  @doc """
  Set user id for session creation
  """
  @spec set_user_id(Conn.t(), any) :: Conn.t()
  def set_user_id(conn, user_id), do: Conn.put_private(conn, @private_user_id_key, user_id)

  defp set_tst(conn, tst), do: Conn.put_private(conn, @private_token_signature_transport_key, tst)
end
