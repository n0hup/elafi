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
        Logger.info("Started listener on #{ip_to_string(udp_ip)} : #{udp_port}")
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
           nscount::unsigned-integer-size(16), arcount::unsigned-integer-size(16),
           rest::binary>>},
        state
      ) do
    parsed_header =
      {:id, id, :qr, qr, :opcode, opcode, :aa, aa, :tc, tc, :rd, rd, :ra, ra, :z, z, :rcode,
       rcode, :qdcount, qdcount, :ancount, ancount, :nscount, nscount, :arcount, arcount}

    parsed_question = parse_dns_question(rest)

    Logger.info("Received DNS packet #{inspect(parsed_header)} #{inspect(parsed_question)}")

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

  defp parse_dns_question(bin) do
    parse_dns_question_acc({bin, {}, 1, true})
  end

  # defp parse_dns_question_acc(
  #        <<0::8, 0::8, qtype0::8, qtype1::8, qclass0::8, qclass1::8>>,
  #        acc,
  #        _l,
  #        _f
  #      ) do
  #   Logger.info(
  #     "Parsing DNS question(0) -> ret: #{inspect({qtype0, qtype1, qclass0, qclass1})} #{
  #       inspect(acc)
  #     }"
  #   )

  #   qtype = get_qtype({qtype0, qtype1})
  #   qclass = get_qclass({qclass0, qclass1})
  #   return = {:q, acc, :qtype, qtype, :qclass, qclass}
  #   Logger.info("Parsing DNS question(0) -> ret: #{inspect(return)}")
  #   return
  # end

  defp parse_dns_question_acc(args) do
    Logger.info("Parsing DNS question(0) -> args: #{inspect(args)}")

    case args do
      {<<0::8, 0::8, qtype0::8, qtype1::8, qclass0::8, qclass1::8, _rest::bits>>, acc, _, _} ->
        qtype = get_qtype({qtype0, qtype1})
        qclass = get_qclass({qclass0, qclass1})
        return = {:q, acc, :qtype, qtype, :qclass, qclass}
        Logger.info("Parsing DNS question(return) -> ret: #{inspect(return)}")
        return

      {bin, acc, 1, true} ->
        <<v::8, tail::bits>> = bin

        parse_dns_question_acc({
          tail,
          Tuple.append(acc, v),
          v,
          false
        })

      {bin, acc, l, false} ->
        value = take_n_bits(bin, l, <<>>)
        r = l * 8
        <<_head::size(r), tail::bits>> = bin
        parse_dns_question_acc({tail, Tuple.append(acc, value), 1, true})
    end
  end

  defp take_n_bits(_bin, 0, acc) do
    Logger.info("Taking bits -> v: #{inspect('none')} n: #{inspect(0)} acc: #{inspect(acc)}")
    acc
  end

  defp take_n_bits(<<v::8, rest::bits>>, n, acc) do
    Logger.info("Taking bits -> v: #{inspect(v)} n: #{inspect(n)} acc: #{inspect(acc)}")
    take_n_bits(rest, n - 1, acc <> <<v>>)
  end

  defp get_qtype(qtype) do
    case qtype do
      {1, 0} -> 'A'
      {2, 0} -> 'NS'
      {5, 0} -> 'CNAME'
      {6, 0} -> 'SOA'
      {12, 0} -> 'PTR'
      {15, 0} -> 'MX'
      {28, 0} -> 'AAAA'
      {33, 0} -> 'SRV'
      {255, 0} -> 'ANY'
    end
  end

  defp get_qclass(qclass) do
    case qclass do
      {1, 0} -> 'IN'
    end
  end

  def id_atom, do: __MODULE__

  defp ip_to_string({o0, o1, o2, o3}), do: "#{o0}.#{o1}.#{o2}.#{o3}"
  # TODO ipv6 too defp ip_to_string({o0, o1, o2, o3}) do: "#{o0}.#{o1}.#{o2}.#{o3}"
end
