defmodule YipyipExAuth.Plugs.ProcessAccessTokenTest do
  use ExUnit.Case
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

  doctest YipyipExAuth.Plugs.ProcessAccessToken
end
