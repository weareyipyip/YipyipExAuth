defmodule YipyipExAuth.Models.Session do
  @moduledoc """
  A session.
  """
  defstruct id: nil,
            user_id: nil,
            refresh_token_id: nil,
            created_at: nil,
            refreshed_at: nil,
            last_known_ip: nil,
            token_signature_transport: nil,
            expires_at: nil

  @type t :: %__MODULE__{
          id: String.t(),
          user_id: pos_integer,
          refresh_token_id: String.t(),
          created_at: integer,
          refreshed_at: integer,
          last_known_ip: String.t(),
          token_signature_transport: atom,
          expires_at: integer | nil
        }
end
