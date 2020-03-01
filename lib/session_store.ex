defmodule YipyipExAuth.SessionStore do
  @moduledoc """
  Behaviour definition of a persistent session store, to be implemented by the application.
  The implementation is expected to handle cleanup of expired entries.
  """
  alias YipyipExAuth.Models.Session

  @doc """
  Delete session with id `session_id` for user with id `user_id`.

  Implementations may choose to ignore user_id, since session_id is unique by itself.
  """
  @callback delete(session_id :: binary, user_id :: binary) :: :ok | {:error, binary}

  @doc """
  Insert or update #{Session} `session`, with time-to-live `ttl`.

  The session_id and user_id are taken from the `session` struct.
  Implementations may choose to ignore user_id, since session_id is unique by itself.
  """
  @callback upsert(session :: Session.t(), ttl :: integer) :: :ok | {:error, binary}

  @doc """
  Get session with id `session_id` for user with id `user_id`.

  Implementations may choose to ignore user_id, since session_id is unique by itself.
  """
  @callback get(session_id :: binary, user_id :: binary) :: Session.t() | nil | {:error, binary}
end
