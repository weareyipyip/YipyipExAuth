defmodule YipyipExAuth.SessionStore do
  @moduledoc """
  Behaviour definition of a persistent session store, to be implemented by the application.
  The implementation is expected to handle cleanup of expired entries.

  All three callbacks can use only a session ID, and ignore the user ID that is passed in as well, because a session ID is a unique 128-bits binary by itself. However, not ignoring the user ID enables the use case where all sessions for a user are fetched or logged out, for example, so there are benefits to storing sessions per user.

  Reference Redis implementation (requires [`Redix`](https://hexdocs.pm/redix) and assumes a module has been configured for it according to its documentation):
  ```
  defmodule MyAppWeb.RedisSessionStore do
    @behaviour YipyipExAuth.SessionStore
    alias MyApp.MyRedix

    @key_prefix "SESSION_STORE_"

    @impl true
    def get(session_id, user_id) do
      ["GET", session_key(session_id, user_id)]
      |> MyRedix.command()
      |> case do
        {:ok, session} when not is_nil(session) -> deserialize(session)
        {:ok, nil} -> nil
        error -> error
      end
    end

    @impl true
    def upsert(%{id: session_id, user_id: user_id} = session, ttl) do
      ["SETEX", session_key(session_id, user_id), Integer.to_string(ttl), serialize(session)]
      |> MyRedix.command()
      |> case do
        {:ok, _} -> :ok
        error -> error
      end
    end

    @impl true
    def delete(session_id, user_id) do
      ["DEL", session_key(session_id, user_id)]
      |> MyRedix.command()
      |> case do
        {:ok, _} -> :ok
        error -> error
      end
    end

    def get_all(user_id) do
      with {:ok, keys} when keys != [] <- find_session_keys(user_id),
          {:ok, values} <- MyRedix.command(["MGET" | keys]) do
        Enum.map(values, &deserialize/1)
      else
        {:ok, []} -> []
        other -> other
      end
    end

    def delete_all(user_id) do
      with {:ok, keys} when keys != [] <- find_session_keys(user_id),
          {:ok, _count} <- MyRedix.command(["DEL" | keys]) do
        :ok
      else
        {:ok, []} -> :ok
        other -> other
      end
    end

    #####################
    # Private functions #
    #####################

    defp serialize(session), do: :erlang.term_to_binary(session)
    defp deserialize(binary), do: :erlang.binary_to_term(binary)

    # keys as IO lists to prevent unnecessary string concatenation overhead
    defp session_key(session_id, user_id), do: [@key_prefix, ".", user_id, ".", session_id]

    # SCAN is not atomic. New sessions created during the scan may not be found.
    defp find_session_keys(user_id, scan_iteration \\\\ nil, results \\\\ [])

    defp find_session_keys(_user_id, "0", results) do
      {:ok, Enum.uniq(results)}
    end

    defp find_session_keys(user_id, scan_iteration, results) do
      ["SCAN", scan_iteration, "MATCH", session_key("*", user_id)]
      |> MyRedix.command()
      |> case do
        {:ok, [scan_iteration | [partial_results]]} ->
          find_session_keys(user_id, scan_iteration, partial_results ++ results)

        error ->
          error
      end
    end
  end
  ```
  """
  alias YipyipExAuth.Models.Session

  @doc """
  Delete session with id `session_id` for user with id `user_id`.

  Implementations may choose to ignore `user_id`, since `session_id` is unique by itself.
  """
  @callback delete(session_id :: binary, user_id :: binary | pos_integer()) ::
              :ok | {:error, binary}

  @doc """
  Insert or update #{Session} `session`, with time-to-live `ttl`.

  The `session_id` and `user_id` are taken from the `session` struct.
  Implementations may choose to ignore `user_id`, since `session_id` is unique by itself.
  """
  @callback upsert(session :: Session.t(), ttl :: integer) :: :ok | {:error, binary}

  @doc """
  Get session with id `session_id` for user with id `user_id`.

  Implementations may choose to ignore `user_id`, since `session_id` is unique by itself.
  """
  @callback get(session_id :: binary, user_id :: binary | pos_integer()) ::
              Session.t() | nil | {:error, binary}
end
