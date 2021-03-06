defmodule Elafi.MixProject do
  use Mix.Project

  def project do
    [
      apps_path: "apps",
      version: "0.1.0",
      start_permanent: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      releases: [
        elafi: [
          applications: [dnscache: :permanent, webui: :permanent, dataz: :permanent]
        ]
      ]
    ]
  end

  defp deps do
    []
  end
end
