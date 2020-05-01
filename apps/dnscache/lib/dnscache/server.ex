defmodule Dnscache.Server do
  use GenServer
  require Logger

  def start_link(args) do
    Logger.info("Dnscache.Server is starting")
    Logger.info("Dnscache.Server.start_link, args: #{inspect(args)}")
    udp_ip = Application.get_env(:dnscache, :udp_ip_listen, {127, 0, 0, 1})
    udp_port = Application.get_env(:dnscache, :udp_port_listen, 5355)
    GenServer.start_link(__MODULE__, [udp_ip, udp_port], name: Dnscache.Server)
  end

  def init([udp_ip, udp_port]) do
    Logger.info("Dnscache.Server.init, args: #{inspect([udp_ip, udp_port])}")

    case :gen_udp.open(udp_port, [:binary, {:active, true}, {:ip, udp_ip}]) do
      {:ok, udp_socket} ->
        Logger.info("Started listener on #{udp_ip} : #{udp_port}")
        {:ok, %{ip: udp_ip, port: udp_port, socket: udp_socket}}

      {:error, reason} ->
        Logger.error("Could NOT start listener on #{udp_ip} : #{udp_port}, reason: #{reason}")
        {:error, reason}
    end
  end

  def handle_info(
        {:udp, socket, source_ip, source_port,
         <<id::16, qr::1, opcode::4, aa::1, tc::1, rd::1, ra::1, z::3, rcode::4,
           qdcount::unsigned-integer-size(16), ancount::unsigned-integer-size(16),
           nscount::unsigned-integer-size(16), arcount::unsigned-integer-size(16), qname::32,
           qtype::16, qclass::16, _rest::binary>>},
        state
      ) do
    parsed_query =
      {:id, id, :qr, qr, :opcode, opcode, :aa, aa, :tc, tc, :rd, rd, :ra, ra, :z, z, :rcode,
       rcode, :qdcount, qdcount, :ancount, ancount, :nscount, nscount, :arcount, arcount, :qname,
       qname, :qtype, qtype, :qclass, qclass}

    Logger.info("Received DNS packet #{inspect(parsed_query)}")

    :gen_udp.send(socket, source_ip, source_port, <<0::16>>)
    {:noreply, state}
  end

  def handle_info({:udp, socket, source_ip, source_port, packet}, state) do
    Logger.info("Received packet #{inspect(packet)}")
    :gen_udp.send(socket, source_ip, source_port, packet)
    {:noreply, state}
  end

  # defp create_response() do
  #   <<id::16, qr::1, opcode::4, aa::1, tc::1, rd::1, ra::1, z::3, rcode::4, _rest::binary>>
  # end

  def id_atom, do: __MODULE__
end
