defmodule YipyipExAuth.MixProject do
  use Mix.Project

  def project do
    [
      app: :yipyip_ex_auth,
      version: "0.1.0-alpha.2",
      elixir: "~> 1.9",
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
      {:dialyxir, "~> 1.0.0-rc.7", only: [:dev, :test], runtime: false},
      {:phoenix, "~> 1.4"}
    ]
  end
end
