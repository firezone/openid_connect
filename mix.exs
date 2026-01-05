defmodule OpenIDConnect.Mixfile do
  use Mix.Project

  @version "1.0.0"

  def project do
    [
      app: :openid_connect,
      version: @version,
      elixir: "~> 1.18",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      description: description(),
      package: package(),
      name: "OpenID Connect",
      deps: deps(),
      docs: docs(),
      source_url: "https://github.com/DockYard/openid_connect",
      test_coverage: [tool: ExCoveralls],
      test_ignore_filters: [~r"/fixtures/"]
    ]
  end

  def cli do
    [
      preferred_envs: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ]
    ]
  end

  defp elixirc_paths(:test), do: elixirc_paths(nil) ++ ["test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def application do
    [
      mod: {OpenIDConnect.Application, []},
      extra_applications: [:logger]
    ]
  end

  def description do
    """
    OpenID Connect for Elixir
    """
  end

  def docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      logo: "openid-logo.png",
      extras: ["README.md"]
    ]
  end

  def package do
    [
      maintainers: ["Brian Cardarella"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/DockYard/openid_connect"},
      files: ~w(lib mix.exs README.md LICENSE.md CHANGELOG.md)
    ]
  end

  defp deps do
    [
      {:req, "~> 0.5"},
      {:jose, "~> 1.11"},

      # Test deps
      {:earmark, "~> 1.2", only: :dev},
      {:credo, "~> 1.6", only: :dev},
      {:dialyxir, "~> 1.2", only: :dev},
      {:ex_doc, "~> 0.18", only: :dev},
      {:excoveralls, "~> 0.14", only: :test},
      {:plug_cowboy, "~> 2.6", only: :test},
      {:bypass, "~> 2.1", only: :test}
    ]
  end
end
