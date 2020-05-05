defmodule Dnscache.Server do
  use GenServer
  require Logger

  @spec start_link(any) :: :ignore | {:error, any} | {:ok, pid}
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

      {:error, :eacces} ->
        Logger.error(
          "Could NOT start listener on #{ip_to_string(udp_ip)} : #{udp_port}, reason:  Permission denied"
        )

        {:error, "Permission denied"}

      {:error, reason} ->
        Logger.error(
          "Could NOT start listener on #{ip_to_string(udp_ip)} : #{udp_port}, reason: #{
            inspect(reason)
          }"
        )

        {:error, reason}
    end
  end

  def handle_info(
        {
          :udp,
          socket,
          source_ip,
          source_port,
          <<query_header_id_raw::unsigned-integer-size(16), query_header_flags_raw::bits-size(16),
            query_header_qdcount_raw::unsigned-integer-size(16),
            query_header_ancount_raw::unsigned-integer-size(16),
            query_header_nscount_raw::unsigned-integer-size(16),
            query_header_arcount_raw::unsigned-integer-size(16), query_rest_raw::bits>>
        },
        state
      ) do
    Logger.info(
      "handle_info #{
        inspect(
          {:query_header_id_raw, query_header_id_raw, :query_header_flags_raw,
           query_header_flags_raw, query_header_qdcount_raw, query_header_qdcount_raw,
           :query_header_ancount_raw, query_header_ancount_raw, :query_header_nscount_raw,
           query_header_nscount_raw, :query_header_arcount_raw, query_header_arcount_raw,
           :query_rest_raw, query_rest_raw}
        )
      }"
    )

    Logger.info("parse_header_flags: #{inspect(parse_header_flags(query_header_flags_raw))}")

    {:question_qname_raw, question_qname_raw, :question_qtype_int, question_qtype_int,
     :question_qclass_int, question_qclass_int, :question_parsed,
     {question_qname_parsed, question_qtype_string, question_qclass_string}, :rest,
     query_rest_raw_after_question} = parse_dns_question(query_rest_raw)

    for <<x::bits-size(8) <- question_qname_raw>>, do: Logger.info("#{inspect(x)}")

    Logger.info(
      "handle_info #{
        inspect(
          {:qname, question_qname_parsed, :qtype, question_qtype_string, :qclass,
           question_qclass_string}
        )
      }"
    )

    if query_header_arcount_raw == 1 do
      {:ok, :ok} = parse_dns_additional(query_rest_raw_after_question)
      for <<x::bits-size(8) <- query_rest_raw_after_question>>, do: Logger.info("#{inspect(x)}")
    end

    create_reponse_header(query_header_id_raw)

    :gen_udp.send(socket, source_ip, source_port, create_reponse_header(query_header_id_raw))
    {:noreply, state}
  end

  def handle_info(
        {
          :udp,
          socket,
          source_ip,
          source_port,
          catch_all
        },
        state
      ) do
    Logger.error("Received DNS packet (catch_all) #{inspect(catch_all)}")

    :gen_udp.send(socket, source_ip, source_port, catch_all)
    {:noreply, state}
  end

  defp parse_dns_additional(<<1::1, 1::1, rest::bits>>) do
    Logger.info("parse_dns_additional(pointer) #{inspect(rest)}")
    {:ok, :ok}
  end

  defp parse_dns_additional(dns_additional) do
    Logger.info("parse_dns_additional(label) #{inspect(dns_additional)}")

    {:ok, :ok}
  end

  defp parse_dns_question(query_rest_raw) do
    [question_qname_raw, rest] = :binary.split(query_rest_raw, <<0::8>>)
    Logger.info("#{inspect(question_qname_raw)} : #{inspect(rest)}")
    <<question_qtype_int::16, question_qclass_int::16, remaining::bits>> = rest

    question_qname_parsed = for <<len, name::binary-size(len) <- question_qname_raw>>, do: name
    question_qtype_string = qtype_to_string(question_qtype_int)
    question_qclass_string = qclass_to_string(question_qclass_int)

    return = {:question_qname_raw, question_qname_raw, :question_qtype_int, question_qtype_int,
    :question_qclass_int, question_qclass_int, :question_parsed,
    {question_qname_parsed, question_qtype_string, question_qclass_string}, :rest, remaining}

    Logger.info("#{inspect(return)}")

    {:question_qname_raw, question_qname_raw, :question_qtype_int, question_qtype_int,
     :question_qclass_int, question_qclass_int, :question_parsed,
     {question_qname_parsed, question_qtype_string, question_qclass_string}, :rest, remaining}
  end

  defp generate_dns_question(question) do
    List.foldl(question, [], fn x, acc -> [x] ++ [String.length(x)] ++ acc end)
  end

  defp parse_header_flags(
         <<qr::unsigned-integer-size(1), opcode::unsigned-integer-size(4),
           aa::unsigned-integer-size(1), tc::unsigned-integer-size(1),
           rd::unsigned-integer-size(1), ra::unsigned-integer-size(1),
           res1::unsigned-integer-size(1), res2::unsigned-integer-size(1),
           res3::unsigned-integer-size(1), rcode::unsigned-integer-size(4)>>
       ) do
    {:qr, qr, :opcode, opcode, :aa, aa, :tc, tc, :rd, rd, :ra, ra, :res1, res1, :res2, res2,
     :res3, res3, :rcode, rcode}
  end

  defp create_reponse_header(id) do
    qr = 1
    opcode = 0
    aa = 0
    tc = 0
    rd = 1
    ra = 1
    rcode = 0
    qdcount = 1
    ancount = 1
    nscount = 0
    arcount = 1

    <<id::16, qr::1, opcode::4, aa::1, tc::1, rd::1, ra::1, 0::3, rcode::4, qdcount::16,
      ancount::16, nscount::16, arcount::16>>
  end

  defp create_response_answer() do
    <<60::32>> <> <<4::16>> <> <<127::8, 0::8, 0::8, 1::88>>
  end

  defp qtype_to_string(qtype) do
    case qtype do
      1 -> {:ok, 'A'}
      2 -> {:ok, 'NS'}
      5 -> {:ok, 'CNAME'}
      6 -> {:ok, 'SOA'}
      12 -> {:ok, 'PTR'}
      15 -> {:ok, 'MX'}
      28 -> {:ok, 'AAAA'}
      33 -> {:ok, 'SRV'}
      255 -> {:ok, 'ANY'}
      _ -> {:error, 'NONE'}
    end
  end

  defp string_to_qtype(qtype) do
    case qtype do
      'A' -> {:ok, 1}
      'NS' -> {:ok, 2}
      'CNAME' -> {:ok, 5}
      'SOA' -> {:ok, 6}
      'PTR' -> {:ok, 12}
      'MX' -> {:ok, 15}
      'AAAA' -> {:ok, 28}
      'SRV' -> {:ok, 33}
      'ANY' -> {:ok, 255}
      _ -> {:error, :notfound}
    end
  end

  defp qclass_to_string(qclass) do
    case qclass do
      1 -> {:ok, 'IN'}
      _ -> {:error, 'NONE'}
    end
  end

  defp string_to_qclass(qclass) do
    case qclass do
      'IN' -> {:ok, 1}
      _ -> {:error, {0}}
    end
  end

  # TODO: convert qname to a list
  defp get_name(qname) do
    :erlang.list_to_binary(Tuple.to_list(qname))
  end

  @spec encode_ip({integer, integer, integer, integer}) :: <<_::32>>
  def encode_ip({a, b, c, d}), do: <<a, b, c, d>>

  @spec id_atom :: Dnscache.Server
  def id_atom, do: __MODULE__

  defp ip_to_string({o0, o1, o2, o3}), do: "#{o0}.#{o1}.#{o2}.#{o3}"
  # TODO ipv6 too defp ip_to_string({o0, o1, o2, o3}) do: "#{o0}.#{o1}.#{o2}.#{o3}"
end
