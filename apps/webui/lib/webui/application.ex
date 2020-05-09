defmodule Webui.Application do
  # use Application
  # alias :elli, as: Elli

  def start(_type, _args) do
    #   children = [
    #     {Elli, []},
    #     {Webui.Server, []}
    #   ]

    opts = [strategy: :one_for_one, name: Webui.Supervisor]
    Supervisor.start_link([], opts)
  end
end
