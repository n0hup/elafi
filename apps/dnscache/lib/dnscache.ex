defmodule Dnscache do
  use Application
  require Logger

  def start(_type, _args) do
    import Supervisor.Spec, warn: true

    {_, _, micro} = :os.timestamp()

    # :rand.seed(micro)
    # :rand.seed(:exs64)

    children = []

    opts = [strategy: :one_for_one, name: Dnscache.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
