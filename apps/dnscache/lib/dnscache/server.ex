defmodule Dnscache.Server do
  use GenServer
  require Logger
  alias :mnesia, as: Mnesia
  alias :gen_udp, as: GenUdp

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

    case Mnesia.create_schema([node()]) do
      :ok ->
        Logger.info("Created Mnesia folder")

      {:error, {_node0, {:already_exists, _node1}}} ->
        Logger.info("Mnesia folder was previously created")

      {:error, reason} ->
        Logger.error("Mnesia folder creation error #{inspect(reason)}")
    end

    case Mnesia.start() do
      :ok ->
        Logger.info("Mnesia is started")

      {:error, reason} ->
        Logger.info("Mnesia could not be started #{inspect(reason)}")
    end

    case :gen_udp.open(udp_port, [:binary, {:active, true}, {:ip, udp_ip}]) do
      {:ok, udp_socket} ->
        Logger.info("Started listener on #{ip_to_string(udp_ip)} : #{udp_port}")

        case GenUdp.open(0, [:binary, {:active, false}]) do
          {:ok, client_socket} ->
            Logger.info(
              "Client UDP socket was succssfully opened, socket: #{inspect(client_socket)}"
            )

            {:ok, %{ip: udp_ip, port: udp_port, socket: udp_socket, client_socket: client_socket}}

          {:error, reason} ->
            Logger.error("Client UDP socket could not be opened, error: #{inspect(reason)}")
            {:ok, "Client UDP socket error"}
        end

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
          dns_query_raw
        },
        state
      )
      when byte_size(dns_query_raw) < 513 do
    {:ok, :ok} = parse_query(dns_query_raw)

    :gen_udp.send(state[:client_socket], {1, 1, 1, 1}, 53, dns_query_raw)

    # This can be :ok or :error - needs a strategy of retry
    {:ok, {_ip, _port, resp}} = :gen_udp.recv(state[:client_socket], 0, 5_000)

    # {:error, :timeout}

    :gen_udp.send(
      socket,
      source_ip,
      source_port,
      resp
    )

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

  #
  ## PROCESSING DNS PACKETS
  #

  defp parse_query(
         <<query_header_id_raw::unsigned-integer-size(16), qr::unsigned-integer-size(1),
           opcode::unsigned-integer-size(4), aa::unsigned-integer-size(1),
           tc::unsigned-integer-size(1), rd::unsigned-integer-size(1),
           ra::unsigned-integer-size(1), res1::unsigned-integer-size(1),
           res2::unsigned-integer-size(1), res3::unsigned-integer-size(1),
           rcode::unsigned-integer-size(4), query_header_qdcount_raw::unsigned-integer-size(16),
           query_header_ancount_raw::unsigned-integer-size(16),
           query_header_nscount_raw::unsigned-integer-size(16),
           query_header_arcount_raw::unsigned-integer-size(16), query_rest_raw::bits>>
       ) do
    {:query_question_qname_raw, query_question_qname_raw, :query_question_qtype_int,
     query_question_qtype_int, :query_question_qclass_int, query_question_qclass_int,
     :query_question_parsed,
     {query_question_qname_parsed, query_question_qtype_string, query_question_qclass_string},
     :rest, query_rest_after_question_raw} = parse_dns_question(query_rest_raw)

    query_header_question =
      {:header,
       {:query_header_id_raw, query_header_id_raw, :qr, qr, :opcode, opcode, :aa, aa, :tc, tc,
        :rd, rd, :ra, ra, :res1, res1, :res2, res2, :res3, res3, :rcode, rcode,
        :query_header_qdcount_raw, query_header_qdcount_raw, :query_header_ancount_raw,
        query_header_ancount_raw, :query_header_nscount_raw, query_header_nscount_raw,
        :query_header_arcount_raw, query_header_arcount_raw}, :question,
       {:query_question_parsed, query_question_qname_parsed, :query_question_qtype_string,
        query_question_qtype_string, :query_question_qclass_string, query_question_qclass_string}}

    Logger.info("#{inspect(query_header_question)}")

    if query_header_arcount_raw == 1 do
      {:ok, :ok} = parse_dns_additional(query_rest_after_question_raw)
    end

    {:ok, :ok}
  end

  defp parse_dns_additional(bin) do
    Logger.info("parse_dns_additional(pointer) #{inspect(bin)}")
    for <<x::bits-size(16) <- bin>>, do: Logger.info("#{inspect(x)}")
    {:ok, :ok}
  end

  defp parse_dns_additional(bin) do
    Logger.info("parse_dns_additional(pointer) #{inspect(bin)}")
    for <<x::bits-size(8) <- bin>>, do: Logger.info("#{inspect(x)}")
    {:ok, :ok}
  end

  defp parse_dns_question(query_rest_raw) do
    [query_question_qname_raw, rest] = :binary.split(query_rest_raw, <<0::8>>)
    <<query_question_qtype_int::16, query_question_qclass_int::16, remaining::bits>> = rest

    query_question_qname_parsed =
      for <<len, name::binary-size(len) <- query_question_qname_raw>>, do: name

    query_question_qtype_string = qtype_to_string(query_question_qtype_int)
    query_question_qclass_string = qclass_to_string(query_question_qclass_int)

    return =
      {:query_question_qname_raw, query_question_qname_raw, :query_question_qtype_int,
       query_question_qtype_int, :query_question_qclass_int, query_question_qclass_int,
       :query_question_parsed,
       {query_question_qname_parsed, query_question_qtype_string, query_question_qclass_string},
       :rest, remaining}

    Logger.info("#{inspect(return)}")

    {:query_question_qname_raw, query_question_qname_raw, :query_question_qtype_int,
     query_question_qtype_int, :query_question_qclass_int, query_question_qclass_int,
     :query_question_parsed,
     {query_question_qname_parsed, query_question_qtype_string, query_question_qclass_string},
     :rest, remaining}
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

  defp create_response_answer(name, type, class, ttl, rlength, rdata) do
    name <> <<type::16>> <> <<class::16>> <> <<ttl::32>> <> <<rlength::16>> <> rdata
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
      _ -> {:error, 0}
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
