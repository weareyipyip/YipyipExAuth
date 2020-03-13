defmodule YipyipExAuth.TestSupport.Shared do
  alias Plug.Conn
  alias YipyipExAuth.TestSupport.FakeEndpoint

  def build_conn() do
    %Conn{remote_ip: {127, 0, 0, 1}, private: %{phoenix_endpoint: FakeEndpoint}}
  end
end
