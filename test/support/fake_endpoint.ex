defmodule YipyipExAuth.TestSupport.FakeEndpoint do
  def config(:secret_key_base), do: "supersupersecretvalue"
  def config(key), do: IO.puts("Endpoint config requested: #{key}")
end
