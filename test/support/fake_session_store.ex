defmodule YipyipExAuth.TestSupport.FakeSessionStore do
  alias YipyipExAuth.Models.Session

  def delete(_, _), do: :ok
  def upsert(_, _), do: :ok
  def get(_, _), do: %Session{id: "a", user_id: 1, refresh_token_id: "a"}
end
