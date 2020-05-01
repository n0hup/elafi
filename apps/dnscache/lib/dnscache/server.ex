defmodule Dnscache.Server do

	use GenServer
	require Logger

  def start_link(args) do
		Logger.info("Dnscache.Server is starting")
		Logger.info("Dnscache.Serverstart_link, args: #{inspect args}")
		GenServer.start_link(__MODULE__, :ok)
  end

  def init(args) do
		Logger.info("Dnscache.Server.init, args: #{inspect args}")
  	{:ok, args}
  end

	def get_my_state(pid) do
		GenServer.call(pid, {:example})
	end

	def say_my_name() do
		self() 
	end

	# Callbacks

  def handle_call(message, from, state) do
		Logger.info("Dnscache.Server.handle_call, args: #{inspect {message, from, state}}")
		{:reply, state, state}
  end

end
