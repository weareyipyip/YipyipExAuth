defmodule YipyipExAuth.SharedInternals do
  @moduledoc false
  # module consists of shared functions internal to the package
  use YipyipExAuth.Utils.Constants
  require Logger
  alias Plug.Conn

  @doc false
  # this also works if expires_at is an atom like nil, because of https://hexdocs.pm/elixir/master/operators.html#term-ordering
  def session_expired?(session_id, user_id, expires_at, session_store_module) do
    if expires_at > System.system_time(:second) do
      {:session_expired, false}
    else
      session_store_module.delete(session_id, user_id)
      {:session_expired, true}
    end
  end

  @doc false
  def get_token(conn, signature_cookie_name) do
    bearer_token = token_from_auth_header(conn)

    cookie_signature =
      conn |> Conn.fetch_cookies() |> Map.get(:cookies, %{}) |> Map.get(signature_cookie_name)

    {:token,
     cond do
       bearer_token && cookie_signature -> {:cookie, bearer_token <> cookie_signature}
       bearer_token -> {:bearer, bearer_token}
       true -> nil
     end}
  end

  @doc false
  def auth_error(conn, error), do: Conn.put_private(conn, @private_auth_error_key, error)

  @doc false
  def compress_access_payload(pl), do: {pl.uid, pl.sid, pl.tst == :cookie, pl.exp, pl.epl}

  @doc false
  def decompress_access_payload({uid, sid, cookie?, exp, epl}) do
    {:ok, %{uid: uid, sid: sid, tst: if(cookie?, do: :cookie, else: :bearer), exp: exp, epl: epl}}
  end

  def decompress_access_payload(_), do: {:error, :invalid_payload}

  @doc false
  def compress_refresh_payload(pl), do: {pl.id, pl.uid, pl.sid, pl.tst == :cookie, pl.exp, pl.epl}

  @doc false
  def decompress_refresh_payload({id, uid, sid, cookie?, exp, epl}) do
    {:ok,
     %{
       id: id,
       uid: uid,
       sid: sid,
       tst: if(cookie?, do: :cookie, else: :bearer),
       exp: exp,
       epl: epl
     }}
  end

  def decompress_refresh_payload(_), do: {:error, :invalid_payload}

  ############
  # Privates #
  ############

  defp token_from_auth_header(conn) do
    conn
    |> Conn.get_req_header("authorization")
    |> List.first()
    |> auth_header_to_token()
    |> case do
      "" -> nil
      other -> other
    end
  end

  defp auth_header_to_token(<<"Bearer "::binary, token::binary>>), do: token
  defp auth_header_to_token(<<"Bearer: "::binary, token::binary>>), do: token
  defp auth_header_to_token(_), do: nil
end
