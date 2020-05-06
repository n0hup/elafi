defmodule Dnscache.Application do
  use Application

  def start(_type, _args) do
    children = [
      {Dnscache.Server, []}
    ]

    opts = [strategy: :one_for_one, name: Dnscache.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
