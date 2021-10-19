if Code.ensure_loaded?(Absinthe) && Code.ensure_loaded?(Absinthe.Plug) do
  defmodule YipyipExAuth.Absinthe.Plugs do
    alias YipyipExAuth.Utils

    @doc """
    Puts `access_token_payload`, `current_user_id` and `refresh_token_payload` in the Absinthe context.
    """
    @spec hydrate_context_plug(Plug.Conn.t(), any) :: Plug.Conn.t()
    def hydrate_context_plug(conn, _opts) do
      Absinthe.Plug.put_options(conn,
        context: %{
          auth: %{
            access_token_payload: Utils.get_access_token_payload(conn),
            current_user_id: Utils.get_user_id(conn),
            refresh_token_payload: Utils.get_refresh_token_payload(conn)
          }
        }
      )
    end
  end
else
  defmodule YipyipExAuth.Absinthe.Plug do
    @moduledoc YipyipExAuth.Absinthe.warning()

    def hydrate_context_plug(_, _), do: raise(YipyipExAuth.Absinthe.warning())
  end
end
