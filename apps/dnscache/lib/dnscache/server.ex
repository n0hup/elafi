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
          <<id::unsigned-integer-size(16), raw_flags::bits-size(16),
            qdcount::unsigned-integer-size(16), ancount::unsigned-integer-size(16),
            nscount::unsigned-integer-size(16), arcount::unsigned-integer-size(16), rest::bits>>
        },
        state
      ) do
    # This has to be debugging once development is done
    if Logger.level() == :info do
      {:qr, qr, :opcode, opcode, :aa, aa, :tc, tc, :rd, rd, :ra, ra, :res1, res1, :res2, res2,
       :res3, res3, :rcode, rcode} = parse_header_flags(raw_flags)

      Logger.info(
        "handle_info id: #{id}, flags: #{
          inspect(
            {:qr, qr, :opcode, opcode, :aa, aa, :tc, tc, :rd, rd, :ra, ra, :res1, res1, :res2,
             res2, :res3, res3, :rcode, rcode}
          )
        }, qdc: #{qdcount}, anc: #{ancount}, nsc: #{nscount}, arc: #{arcount}"
      )
    end

    {:raw_question, raw_question, :parsed_question,
     {:qname, qname, :qtype, qtype, :qclass, qclass}, :rest,
     raw_additional} = parse_dns_question(rest)

    Logger.info("handle_info #{inspect({:qname, qname, :qtype, qtype, :qclass, qclass})}")

    {:ok, _miez} = parse_dns_additional(raw_additional)

    response =
      create_reponse_header(id) <>
        raw_question <> raw_question <> create_response_answer()

    :gen_udp.send(socket, source_ip, source_port, response)
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

  defp parse_dns_additional(bin) do
    Logger.info("parse_dns_additional #{inspect(bin)}")
    {:ok, :ok}
  end

  defp parse_dns_question(bin) do
    [qname_raw, rest] = :binary.split(bin, <<0::8, 0::8>>)

    qname = for <<len, name::binary-size(len) <- qname_raw>>, do: name

    <<qtype0::8, qtype1::8, qclass0::8, qclass1::8, rest::bits>> = rest

    {:ok, qtype} = qtype_to_string({qtype0, qtype1})
    {:ok, qclass} = qclass_to_string({qclass0, qclass1})

    raw_question = qname_raw <> <<0::8, 0::8>> <> <<qtype0::8, qtype1::8, qclass0::8, qclass1::8>>

    {:raw_question, raw_question, :parsed_question,
     {:qname, qname, :qtype, qtype, :qclass, qclass}, :rest, rest}
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

  @spec encode_ip({integer, integer, integer, integer}) :: <<_::32>>
  def encode_ip({a, b, c, d}), do: <<a, b, c, d>>

  @spec id_atom :: Dnscache.Server
  def id_atom, do: __MODULE__

  defp ip_to_string({o0, o1, o2, o3}), do: "#{o0}.#{o1}.#{o2}.#{o3}"
  # TODO ipv6 too defp ip_to_string({o0, o1, o2, o3}) do: "#{o0}.#{o1}.#{o2}.#{o3}"
end
