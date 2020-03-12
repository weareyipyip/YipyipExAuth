defmodule YipyipExAuth.SharedInternalsTest do
  use ExUnit.Case
  # use Plug.Test
  use Phoenix.ConnTest
  alias Plug.Conn
  import Mock
  alias YipyipExAuth.TestSupport.FakeSessionStore

  import YipyipExAuth.SharedInternals

  setup do
    [
      sig_cookie_name: "sig_cookie",
      cookie_sig: ".cookie_sig",
      bearer_token: "header.payload.bearer_sig"
    ]
  end

  describe "&session_expired?/4" do
    test "should return false if not expired" do
      future = System.system_time(:second) + 3600
      assert {:session_expired, false} == session_expired?("a", 1, future, FakeSessionStore)
    end

    test "should return false session lasts forever" do
      infinity = nil
      assert {:session_expired, false} == session_expired?("a", 1, infinity, FakeSessionStore)
    end

    test "should return true if expired and delete session from store" do
      with_mock FakeSessionStore, delete: fn _, _ -> :ok end do
        past = System.system_time(:second) - 3600
        assert {:session_expired, true} == session_expired?("a", 1, past, FakeSessionStore)
        assert_called(FakeSessionStore.delete("a", 1))
      end
    end
  end

  describe "&get_token/2" do
    test "should prefer cookie signature over bearer signature", %{
      sig_cookie_name: sig_cookie_name,
      cookie_sig: cookie_sig,
      bearer_token: bearer_token
    } do
      conn =
        %Conn{}
        |> put_req_cookie(sig_cookie_name, cookie_sig)
        |> Conn.put_req_header("authorization", "Bearer: #{bearer_token}")

      assert {:cookie, bearer_token <> cookie_sig} == get_token(conn, sig_cookie_name)
    end

    test "should fall back to bearer signature", %{
      sig_cookie_name: sig_cookie_name,
      bearer_token: bearer_token
    } do
      conn = %Conn{} |> Conn.put_req_header("authorization", "Bearer #{bearer_token}")
      assert {:bearer, bearer_token} == get_token(conn, sig_cookie_name)
    end

    test "should return nil if authorization header is missing or malformed or does not have bearer token" do
      assert nil == get_token(%Conn{}, "")
      assert nil == get_token(%Conn{} |> Conn.put_req_header("authorization", ""), "")
      assert nil == get_token(%Conn{} |> Conn.put_req_header("authorization", "bearer: a"), "")
      assert nil == get_token(%Conn{} |> Conn.put_req_header("Authorization", "Bearer: a"), "")
      assert nil == get_token(%Conn{} |> Conn.put_req_header("authorization", "Bearer:a"), "")
      assert nil == get_token(%Conn{} |> Conn.put_req_header("authorization", "Bearer: "), "")
      assert nil == get_token(%Conn{} |> Conn.put_req_header("authorization", "Bearer "), "")
    end
  end

  describe "&auth_error/2" do
    test "should work together with `Utils.get_auth_error/1`" do
      assert "boem" == %Conn{} |> auth_error("boem") |> YipyipExAuth.Utils.get_auth_error()
    end
  end
end
