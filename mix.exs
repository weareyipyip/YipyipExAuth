defmodule YipyipExAuth.MixProject do
  use Mix.Project

  def project do
    [
      app: :yipyip_ex_auth,
      version: "0.0.0+development",
      elixir: "~> 1.9",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: """
      YipyipExAuth has been retired and replaced by Charon. Check it out at https://github.com/weareyipyip/charon or https://hexdocs.pm/charon
      """,
      package: [
        name: "yipyip_ex_auth",
        licenses: ["Apache-2.0"],
        links: %{github: "https://github.com/weareyipyip/YipyipExAuth"},
        source_url: "https://github.com/weareyipyip/YipyipExAuth"
      ],
      source_url: "https://github.com/weareyipyip/YipyipExAuth",
      name: "YipyipExAuth",
      docs: [
        source_ref: "master",
        extras: ["./README.md"],
        main: "readme"
      ],
      dialyzer: [
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, "~> 0.21", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.0", only: [:dev, :test], runtime: false},
      {:phoenix, "~> 1.4"},
      # to satisfy phoenix in tests
      {:jason, "~> 1.2", only: [:dev, :test], runtime: false},
      {:mix_test_watch, "~> 1.0", only: [:dev], runtime: false},
      {:mock, "~> 0.3", only: [:test], runtime: false}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
