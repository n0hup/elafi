defmodule Dnscache.Server do
  use GenServer

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, :ok, opts)
  end

  def init(:ok) do
    udp_options = [
      :binary,
      active: 10,
      reuseaddr: true
    ]

    port = Application.get_env(:dnscache, :dns_port)
    {:ok, _socket} = :gen_udp.open(port, udp_options)
  end

  def handle_info({:udp, socket, ip, port, data}, state) do
    :inet.setopts(socket, active: 1)
    IO.inspect([ip, port, data])
    {:noreply, state}
  end
end
