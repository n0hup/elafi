defmodule Dnscache.MixProject do
  use Mix.Project

  def project do
    [
      app: :dnscache,
      version: "0.1.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.7",
      start_permanent: Mix.env() == :prod,
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {Dnscache, [dns_port: 5355]}
    ]
  end

  defp deps do
    [
      {:dns_erlang, ">= 1.1.0"}
    ]
  end
end
