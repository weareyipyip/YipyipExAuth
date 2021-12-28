defmodule YipyipExAuth.PlugsTest do
  use ExUnit.Case
  @moduletag :capture_log
  use YipyipExAuth.Utils.Constants
  alias Plug.Conn
  alias YipyipExAuth.Utils
  alias YipyipExAuth.Models.{Session, Tokens}

  # only available when Mix env = test
  alias YipyipExAuth.TestSupport.FakeSessionStore
  import YipyipExAuth.TestSupport.Shared

  @config YipyipExAuth.Config.from_enum(
            session_ttl: 68400,
            refresh_token_ttl: 3600,
            session_store_module: FakeSessionStore
          )

  import Mock

  import YipyipExAuth.Plugs

  doctest YipyipExAuth.Plugs

  describe "delete_session/2" do
    test "should drop session if present" do
      with_mock FakeSessionStore, delete: fn _, _ -> :ok end do
        build_conn()
        |> Conn.put_private(@private_access_token_payload_key, %{sid: 1, uid: 2})
        |> delete_session(@config)

        assert_called(FakeSessionStore.delete(1, 2))
      end
    end
  end

  describe "create_session/4" do
    test "should raise on store error" do
      with_mock FakeSessionStore, upsert: fn _, _ -> {:error, "boom"} end do
        assert_raise RuntimeError, "session could not be stored", fn ->
          build_conn()
          |> Utils.set_token_signature_transport(:cookie)
          |> Utils.set_user_id(1)
          |> create_session(@config)
        end
      end
    end

    test "should allow sessions with infinite lifespan" do
      conn =
        build_conn()
        |> Utils.set_token_signature_transport(:cookie)
        |> Utils.set_user_id(1)
        |> create_session(%{@config | session_ttl: nil})

      session = Utils.get_session(conn)
      assert session.expires_at == nil
    end

    test "should store sessions with refresh ttl, not session ttl" do
      # if this test fails, unused infinite sessions would keep accumulating in session stores
      with_mock FakeSessionStore, upsert: fn _, _ -> :ok end do
        build_conn()
        |> Utils.set_token_signature_transport(:cookie)
        |> Utils.set_user_id(1)
        |> create_session(@config)

        assert_called(FakeSessionStore.upsert(:_, @config.refresh_token_ttl))
      end
    end

    test "should not create tokens that outlive the session" do
      tokens =
        build_conn()
        |> Utils.set_token_signature_transport(:bearer)
        |> Utils.set_user_id(1)
        |> create_session(%{
          @config
          | session_ttl: 10,
            access_token_ttl: 120,
            refresh_token_ttl: 120
        })
        |> Utils.get_tokens()

      assert tokens.access_token_exp <= System.system_time(:second) + 10
      assert tokens.refresh_token_exp <= System.system_time(:second) + 10
    end

    test "should not create cookies that outlive the session" do
      cookies =
        build_conn()
        |> Utils.set_token_signature_transport(:cookie)
        |> Utils.set_user_id(1)
        |> create_session(%{
          @config
          | session_ttl: 10,
            access_token_ttl: 120,
            refresh_token_ttl: 120
        })
        |> Map.get(:resp_cookies)

      access_cookie = Map.get(cookies, @config.access_cookie_name)
      assert access_cookie.max_age <= 10
      refresh_cookie = Map.get(cookies, @config.refresh_cookie_name)
      assert refresh_cookie.max_age <= 10
    end

    test "should work for old session struct" do
      old_session = %{
        __struct__: YipyipExAuth.Models.Session,
        created_at: nil,
        expires_at: nil,
        id: nil,
        last_known_ip: nil,
        refresh_token_id: nil,
        refreshed_at: nil,
        token_signature_transport: :bearer,
        user_id: 1
      }

      with_mock FakeSessionStore, upsert: fn _, _ -> :ok end do
        assert %Session{extra_payload: %{}} =
                 build_conn()
                 |> Conn.put_private(@private_session_key, old_session)
                 |> create_session(@config)
                 |> Utils.get_session()
      end
    end
  end

  describe "upsert_session/3" do
    test "should raise on store error" do
      with_mock FakeSessionStore, upsert: fn _, _ -> {:error, "boom"} end do
        assert_raise RuntimeError, "session could not be stored", fn ->
          build_conn()
          |> Utils.set_token_signature_transport(:cookie)
          |> Utils.set_user_id(1)
          |> upsert_session(@config)
        end
      end
    end

    test "should allow sessions with infinite lifespan" do
      conn =
        build_conn()
        |> Utils.set_token_signature_transport(:cookie)
        |> Utils.set_user_id(1)
        |> upsert_session(%{@config | session_ttl: nil})

      session = Utils.get_session(conn)
      assert session.expires_at == nil
    end

    test "should store sessions with refresh ttl, not session ttl" do
      # if this test fails, unused infinite sessions would keep accumulating in session stores
      with_mock FakeSessionStore, upsert: fn _, _ -> :ok end do
        build_conn()
        |> Utils.set_token_signature_transport(:cookie)
        |> Utils.set_user_id(1)
        |> upsert_session(@config)

        assert_called(FakeSessionStore.upsert(:_, @config.refresh_token_ttl))
      end
    end

    test "should not create tokens that outlive the session" do
      tokens =
        build_conn()
        |> Utils.set_token_signature_transport(:bearer)
        |> Utils.set_user_id(1)
        |> upsert_session(%{
          @config
          | session_ttl: 10,
            access_token_ttl: 120,
            refresh_token_ttl: 120
        })
        |> Utils.get_tokens()

      assert tokens.access_token_exp <= System.system_time(:second) + 10
      assert tokens.refresh_token_exp <= System.system_time(:second) + 10
    end

    test "should not create cookies that outlive the session" do
      cookies =
        build_conn()
        |> Utils.set_token_signature_transport(:cookie)
        |> Utils.set_user_id(1)
        |> upsert_session(%{
          @config
          | session_ttl: 10,
            access_token_ttl: 120,
            refresh_token_ttl: 120
        })
        |> Map.get(:resp_cookies)

      access_cookie = Map.get(cookies, @config.access_cookie_name)
      assert access_cookie.max_age <= 10
      refresh_cookie = Map.get(cookies, @config.refresh_cookie_name)
      assert refresh_cookie.max_age <= 10
    end

    test "should work for old session struct" do
      old_session = %{
        __struct__: YipyipExAuth.Models.Session,
        created_at: nil,
        expires_at: nil,
        id: nil,
        last_known_ip: nil,
        refresh_token_id: nil,
        refreshed_at: nil,
        token_signature_transport: :bearer,
        user_id: 1
      }

      with_mock FakeSessionStore, upsert: fn _, _ -> :ok end do
        assert %Session{extra_payload: %{}} =
                 build_conn()
                 |> Conn.put_private(@private_session_key, old_session)
                 |> upsert_session(@config)
                 |> Utils.get_session()
      end
    end
  end
end
