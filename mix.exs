defmodule Elafi.MixProject do
  use Mix.Project

  def project do
    [
      apps_path: "apps",
      version: "0.1.0",
      start_permanent: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  defp deps do
    [
      {:esqlite, "~> 0.4.1"},
      {:elli, "~> 3.2"}
    ]
  end
end
