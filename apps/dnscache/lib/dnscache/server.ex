defmodule Dnscache.Server do

	require Logger
	use GenServer

  def start_link(_args) do
		Logger.info("Dnscache.Server is starting")
		GenServer.start_link(__MODULE__, :ok, [])
  end

  def init(args) do
  	{:ok, args}
  end

  def handle_call(message, _from, state) do
    i = String.to_integer(message)
    {:reply, i, state}
  end

end
