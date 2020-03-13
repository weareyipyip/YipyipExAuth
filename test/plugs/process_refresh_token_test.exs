defmodule YipyipExAuth.Plugs.ProcessRefreshTokenTest do
  use ExUnit.Case
  alias Plug.Conn
  alias YipyipExAuth.Plugs.ProcessRefreshToken
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
  @plug_opts ProcessRefreshToken.init(@config)

  import Mock
  alias YipyipExAuth.Models.Session

  describe "&call/2" do
    test "should reject requests when session not found" do
      with_mock FakeSessionStore, get: fn _, _ -> nil end do
        conn =
          build_conn()
          |> put_refresh_token(@config)
          |> ProcessRefreshToken.call(@plug_opts)

        assert %{} == conn.assigns
        assert "session not found" == Utils.get_auth_error(conn)
        assert nil == Utils.get_session(conn)
      end
    end

    test "should reject requests when session user does not match" do
      with_mock FakeSessionStore, get: fn _, _ -> %Session{user_id: 2} end do
        conn =
          build_conn()
          |> put_refresh_token(@config)
          |> ProcessRefreshToken.call(@plug_opts)

        assert %{} == conn.assigns
        assert "session user mismatch" == Utils.get_auth_error(conn)
        assert nil == Utils.get_session(conn)
      end
    end

    test "should reject requests when the refresh token is stale" do
      with_mock FakeSessionStore, get: fn _, _ -> %Session{user_id: 1, refresh_token_id: "b"} end do
        conn =
          build_conn()
          |> put_refresh_token(@config)
          |> ProcessRefreshToken.call(@plug_opts)

        assert %{} == conn.assigns
        assert "refresh token stale" == Utils.get_auth_error(conn)
        assert nil == Utils.get_session(conn)
      end
    end
  end

  doctest YipyipExAuth.Plugs.ProcessRefreshToken
end
