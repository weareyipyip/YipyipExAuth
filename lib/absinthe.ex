if Code.ensure_loaded?(Absinthe) && Code.ensure_loaded?(Absinthe.Plug) do
  defmodule YipyipExAuth.Absinthe do
    @moduledoc """
    Plugs, middlewares etc to use with `Absinthe`.
    """
  end
else
  defmodule YipyipExAuth.Absinthe do
    @warning """
    Absinthe or Absinthe.Plug not found, code is not loaded! Add `{:absinthe_plug, "~> 1.5"}` to your mix.exs dependencies.
    """

    @moduledoc @warning

    @doc @warning
    def warning(), do: @warning
  end
end
