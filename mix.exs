defmodule YipyipExAuth.MixProject do
  use Mix.Project

  def project do
    [
      app: :yipyip_ex_auth,
      version: "0.2.1",
      elixir: "~> 1.9",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: """
      Session manager for Elixir based on stateless access- and stateful refresh (Phoenix) tokens
      """,
      package: [
        name: "yipyip_ex_auth",
        licenses: ["apache-2.0"],
        links: %{github: "https://github.com/weareyipyip/YipyipExAuth"},
        source_url: "https://github.com/weareyipyip/YipyipExAuth"
      ],
      source_url: "https://github.com/weareyipyip/YipyipExAuth",
      name: "YipyipExAuth",
      docs: [
        source_ref: "master",
        extras: ["./README.md"],
        main: "readme"
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
      {:absinthe_plug, "~> 1.5", optional: true},
      # to satisfy phoenix in tests
      {:jason, "~> 1.2", only: [:dev, :test], runtime: false},
      {:mix_test_watch, "~> 1.0", only: [:dev], runtime: false},
      {:mock, "~> 0.3", only: [:test], runtime: false}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
