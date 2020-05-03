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
        {
          :udp,
          socket,
          source_ip,
          source_port,
          <<id::16, qr::1, opcode::4, aa::1, tc::1, rd::1, ra::1, z::3, rcode::4,
            qdcount::unsigned-integer-size(16), ancount::unsigned-integer-size(16),
            nscount::unsigned-integer-size(16), arcount::unsigned-integer-size(16), rest::bits>>
        },
        state
      ) do
    parsed_header =
      {:id, id, :qr, qr, :opcode, opcode, :aa, aa, :tc, tc, :rd, rd, :ra, ra, :z, z, :rcode,
       rcode, :qdcount, qdcount, :ancount, ancount, :nscount, nscount, :arcount, arcount}

    parsed_question = parse_dns_question(rest)
    Logger.info("Received DNS packet #{inspect(parsed_header)} #{inspect(parsed_question)}")
    {:qname, qname, :qtype, qtype, :qclass, qclass} = parsed_question

    response = create_response(id, qname, qtype, qclass)
    Logger.info("Sending DNS packet #{inspect(response)}")

    :gen_udp.send(socket, source_ip, source_port, response)
    {:noreply, state}
  end

  def handle_info({:udp, socket, source_ip, source_port, packet}, state) do
    Logger.info("Received packet #{inspect(packet)}")
    :gen_udp.send(socket, source_ip, source_port, packet)
    {:noreply, state}
  end

  defp parse_dns_question(bin) do
    parse_dns_question_acc({bin, {}, 1, true})
  end

  defp parse_dns_question_acc(args) do
    Logger.info("Parsing DNS question(0) -> args: #{inspect(args)}")

    case args do
      {<<0::8, 0::8, qtype0::8, qtype1::8, qclass0::8, qclass1::8, rest::bits>>, acc, _, _} ->
        # todo error handling?
        {:ok, qtype} = qtype_to_string({qtype0, qtype1})
        {:ok, qclass} = qclass_to_string({qclass0, qclass1})
        return = {:qname, acc, :qtype, qtype, :qclass, qclass}
        Logger.info("Parsing DNS question(return) -> rest: #{inspect(rest)}")
        Logger.info("Parsing DNS question(return) -> ret: #{inspect(return)}")
        return

      {<<v::8, tail::bits>>, acc, 1, true} ->
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

  defp create_response(id, qname, qtype, qclass) do
    # THIS FUNCTION IS A DISASTER ZONE AT THIS STAGE
    # MUST BE CLEANED UP AND SPLIT TO SMALLER CHUNKS
    response_header = create_reponse_header(id)

    #   id,     qr,   op,   aa,   tc,   rd,   ra,   z,    rc,   qdc,   anc,   nsc,   arc
    name = get_name(qname)
    {:ok, type} = string_to_qtype(qtype)
    {:ok, class} = string_to_qclass(qclass)

    # TODO: pls no
    ttl = <<60::unsigned-integer-size(32)>>

    response_answer =
      name <>
        :erlang.list_to_binary(Tuple.to_list(type)) <>
        :erlang.list_to_binary(Tuple.to_list(class)) <>
        ttl <> <<4::unsigned-integer-size(16)>> <> <<155::8, 33::8, 17::8, 68::8>>

    response_header <> response_answer
  end

  defp create_reponse_header(id) do
      <<id::16, 1::1, 0::4, 0::1, 0::1, 0::1, 0::1, 0::3, 0::4, 1::16, 1::16, 0::16, 0::16>>
  end

  defp qtype_to_string(qtype) do
    case qtype do
      {1, 0} -> {:ok, 'A'}
      {2, 0} -> {:ok, 'NS'}
      {5, 0} -> {:ok, 'CNAME'}
      {6, 0} -> {:ok, 'SOA'}
      {12, 0} -> {:ok, 'PTR'}
      {15, 0} -> {:ok, 'MX'}
      {28, 0} -> {:ok, 'AAAA'}
      {33, 0} -> {:ok, 'SRV'}
      {255, 0} -> {:ok, 'ANY'}
      _ -> {:error, 'NONE'}
    end
  end

  defp string_to_qtype(qtype) do
    case qtype do
      'A' -> {:ok, {1, 0}}
      'NS' -> {:ok, {2, 0}}
      'CNAME' -> {:ok, {5, 0}}
      'SOA' -> {:ok, {6, 0}}
      'PTR' -> {:ok, {12, 0}}
      'MX' -> {:ok, {15, 0}}
      'AAAA' -> {:ok, {28, 0}}
      'SRV' -> {:ok, {33, 0}}
      'ANY' -> {:ok, {255, 0}}
      _ -> {:error, {0, 0}}
    end
  end

  defp qclass_to_string(qclass) do
    case qclass do
      {1, 0} -> {:ok, 'IN'}
      _ -> {:error, 'NONE'}
    end
  end

  defp string_to_qclass(qclass) do
    case qclass do
      'IN' -> {:ok, {1, 0}}
      _ -> {:error, {0, 0}}
    end
  end

  # TODO: convert qname to a list
  defp get_name(qname) do
    :erlang.list_to_binary(Tuple.to_list(qname))
  end

  def encode_ip({a, b, c, d}), do: <<a, b, c, d>>

  def id_atom, do: __MODULE__

  defp ip_to_string({o0, o1, o2, o3}), do: "#{o0}.#{o1}.#{o2}.#{o3}"
  # TODO ipv6 too defp ip_to_string({o0, o1, o2, o3}) do: "#{o0}.#{o1}.#{o2}.#{o3}"
end
