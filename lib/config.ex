defmodule YipyipExAuth.Config do
  @moduledoc """
  Config struct. Keys `:session_ttl`, `:refresh_token_ttl` and `:session_store_module` have no defaults and are mandatory.
  Setting `:session_ttl` to `nil` means sessions can live forever, as long as they are refreshed.
  The token salts serve to separate one token from another, the real secret is the endpoint's secret key base.
  Defaults:

  ```
  %Config{
    :refresh_token_ttl,                               # max age of a refresh token
    :session_store_module,                            # an implementation of YipyipExAuth.SessionStore
    :session_ttl,                                     # max age of a session, nil is infinite
    access_token_ttl: 1800,                           # max age of an access token
    access_token_salt: "access_token",                # "namespace" of the access token
    refresh_token_salt: "refresh_token",              # "namespace" of the refresh token
    access_token_key_digest: :sha256,                 # hashing algorithm of the access token
    refresh_token_key_digest: :sha512,                # hashing algorithm of the refresh token
    access_cookie_name: "_access_token_signature",    # name of the access token's signature cookie
    refresh_cookie_name: "_refresh_token_signature",  # name of the refresh token's signature cookie
    access_cookie_opts: [                             # access cookie opts for Plug.Conn.put_resp_cookie/4
      http_only: true,
      extra: "SameSite=Strict",
      secure: true
    ],
    refresh_cookie_opts: [                            # refresh cookie opts for Plug.Conn.put_resp_cookie/4
      http_only: true,
      extra: "SameSite=Strict",
      secure: true
    ]
  }
  ```


  """
  @enforce_keys [:session_ttl, :refresh_token_ttl, :session_store_module]
  defstruct [
    :refresh_token_ttl,
    :session_store_module,
    :session_ttl,
    access_token_ttl: 1800,
    access_token_salt: "access_token",
    refresh_token_salt: "refresh_token",
    access_token_key_digest: :sha256,
    refresh_token_key_digest: :sha512,
    access_cookie_name: "_access_token_signature",
    refresh_cookie_name: "_refresh_token_signature",
    access_cookie_opts: [
      http_only: true,
      extra: "SameSite=Strict",
      secure: true
    ],
    refresh_cookie_opts: [
      http_only: true,
      extra: "SameSite=Strict",
      secure: true
    ]
  ]

  @type t :: %__MODULE__{
          access_token_ttl: pos_integer(),
          refresh_token_ttl: pos_integer(),
          session_store_module: module(),
          session_ttl: pos_integer() | nil,
          access_token_salt: binary(),
          refresh_token_salt: binary(),
          access_token_key_digest: :sha256 | :sha384 | :sha512,
          refresh_token_key_digest: :sha512 | :sha256 | :sha384,
          access_cookie_name: binary(),
          refresh_cookie_name: binary(),
          access_cookie_opts: keyword(),
          refresh_cookie_opts: keyword()
        }

  @doc """
  Build config struct from enumerable (useful for passing in application environment).
  """
  @spec from_enum(Enum.t()) :: %__MODULE__{}
  def from_enum(enum) do
    struct!(__MODULE__, enum)
  end
end
