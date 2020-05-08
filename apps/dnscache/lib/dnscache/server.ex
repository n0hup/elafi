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

    upstream_dns_server_ip =
      Application.get_env(:dnscache, :upstream_dns_server_ip, {192, 168, 1, 105})

    upstream_dns_server_port = Application.get_env(:dnscache, :upstream_dns_server_port, 5335)

    GenServer.start_link(
      __MODULE__,
      [udp_ip, udp_port, upstream_dns_server_ip, upstream_dns_server_port],
      name: Dnscache.Server
    )
  end

  def init([udp_ip, udp_port, upstream_dns_server_ip, upstream_dns_server_port]) do
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

            {:ok,
             %{
               ip: udp_ip,
               port: udp_port,
               socket: udp_socket,
               client_socket: client_socket,
               upstream_dns_server_ip: upstream_dns_server_ip,
               upstream_dns_server_port: upstream_dns_server_port
             }}

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
    #
    ### QUERY
    #

    #
    ## HEADER
    #
    query_header = parse_header(dns_query_raw)
    Logger.debug("#{inspect(query_header)}")

    {:header_id_int, header_id_int, :qr_int, _qr_int, :opcode_int, _opcode_int, :aa_int, _aa_int,
     :tc_int, _tc_int, :rd_int, _rd_int, :ra_int, _ra_int, :res1_int, _res1_int, :res2_int,
     _res2_int, :res3_int, _res3_int, :rcode_int, _rcode_int, :header_qdcount_int,
     _header_qdcount_int, :header_ancount_int, _header_ancount_int, :header_nscount_int,
     _header_nscount_int, :header_arcount_int, header_arcount_int, :rest,
     query_rest_after_header} = query_header

    #
    ## QUESTION
    #
    query_question = parse_question(query_rest_after_header)
    Logger.debug("#{inspect(query_question)}")

    {:question_qname_string, question_qname_string, :question_qtype_int, question_qtype_int,
     :question_qclass_int, question_qclass_int, :rest, query_rest_after_question} = query_question

    question_qtype_string = qtype_to_string(question_qtype_int)
    question_qclass_string = qclass_to_string(question_qclass_int)

    Logger.info(
      "source ip: #{ip_to_string(source_ip)} header_id #{header_id_int} #{question_qname_string} #{
        question_qtype_string
      } #{question_qclass_string}"
    )

    #
    ## ADDITIONAL
    #

    if header_arcount_int == 1 do
      Logger.debug(query_rest_after_question)
      {_, ret} = parse_additional(query_rest_after_question)
      Logger.info("#{inspect(ret)}")
    end

    ##
    ## RIGHT NOW UPSTREAM IS HARDCODED CHANGE HERE TO HAVE QUERY ROUTING
    ##

    #
    ## UPSTREAM
    #

    case send_and_receive(
           state[:client_socket],
           state[:upstream_dns_server_ip],
           state[:upstream_dns_server_port],
           dns_query_raw,
           0
         ) do
      {:ok, {_ip, _port, dns_response_raw}} ->
        Logger.debug("#{inspect(dns_response_raw)}")

      {:error, reason} ->
        Logger.error("#{inspect(reason)}")
    end

    {:noreply, state}
  end

  #
  ## DNS Queries we do not want to deal with, causing error on the client side
  #
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

    :gen_udp.send(socket, source_ip, source_port, <<0::8>>)
    {:noreply, state}
  end

  #
  ## PROCESSING DNS PACKETS
  #

  defp parse_header(
         <<header_id_int::unsigned-integer-size(16), qr_int::unsigned-integer-size(1),
           opcode_int::unsigned-integer-size(4), aa_int::unsigned-integer-size(1),
           tc_int::unsigned-integer-size(1), rd_int::unsigned-integer-size(1),
           ra_int::unsigned-integer-size(1), res1_int::unsigned-integer-size(1),
           res2_int::unsigned-integer-size(1), res3_int::unsigned-integer-size(1),
           rcode_int::unsigned-integer-size(4), header_qdcount_int::unsigned-integer-size(16),
           header_ancount_int::unsigned-integer-size(16),
           header_nscount_int::unsigned-integer-size(16),
           header_arcount_int::unsigned-integer-size(16), rest::bits>>
       ) do
    {:header_id_int, header_id_int, :qr_int, qr_int, :opcode_int, opcode_int, :aa_int, aa_int,
     :tc_int, tc_int, :rd_int, rd_int, :ra_int, ra_int, :res1_int, res1_int, :res2_int, res2_int,
     :res3_int, res3_int, :rcode_int, rcode_int, :header_qdcount_int, header_qdcount_int,
     :header_ancount_int, header_ancount_int, :header_nscount_int, header_nscount_int,
     :header_arcount_int, header_arcount_int, :rest, rest}
  end

  defp parse_question(bin) do
    [question_qname_raw, rest] = :binary.split(bin, <<0::8>>)
    <<question_qtype_int::16, question_qclass_int::16, remaining::bits>> = rest

    question_qname_list = for <<len, name::binary-size(len) <- question_qname_raw>>, do: name
    question_qname_string = Enum.join(question_qname_list, ".")

    {:question_qname_string, question_qname_string, :question_qtype_int, question_qtype_int,
     :question_qclass_int, question_qclass_int, :rest, remaining}
  end

  # EDNS0
  defp parse_additional(<<0::8, 41::16, class::16, ttl::32, rdlen::16, rdata::bits>>) do
    Logger.info("EDNS0 is being processed")
    # +------------+--------------+------------------------------+
    # | Field Name | Field Type   | Description                  |
    # +------------+--------------+------------------------------+
    # | NAME       | domain name  | MUST be 0 (root domain)      |
    # | TYPE       | u_int16_t    | OPT (41)                     |
    # | CLASS      | u_int16_t    | requestor's UDP payload size |
    # | TTL        | u_int32_t    | extended RCODE and flags     |
    # | RDLEN      | u_int16_t    | length of all RDATA          |
    # | RDATA      | octet stream | {attribute,value} pairs      |
    # +------------+--------------+------------------------------+
    {:ok, {class, ttl, rdlen}}
  end

  defp parse_additional(bin) do
    {:ok, :ok}
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

  #
  ## UTILS
  #

  # I do not think this is safe like that
  # I have to match the send and recv packets based on the DNS header id
  defp send_and_receive(socket, remote_ip, remote_port, packet, retry) do
    case :gen_udp.send(
           socket,
           remote_ip,
           remote_port,
           packet
         ) do
      :ok ->
        Logger.debug("Successfully sent UDP request")

        case :gen_udp.recv(socket, 0, 1_500) do
          {:ok, {ip, port, response}} ->
            Logger.debug("Successfully received UDP reponse")
            {:ok, {ip, port, response}}

          {:error, :timeout} ->
            send_and_receive(socket, remote_ip, remote_port, packet, retry + 1)

          {:error, reason} ->
            Logger.error("Could not receive UDP packet, reason #{inspect(reason)}")
            {:error, reason}
        end

      {:error, reason} ->
        Logger.error("Could not send UDP packet, reason #{inspect(reason)}")
        {:error, reason}
    end
  end

  @spec encode_ip({integer, integer, integer, integer}) :: <<_::32>>
  def encode_ip({a, b, c, d}), do: <<a, b, c, d>>

  @spec id_atom :: Dnscache.Server
  def id_atom, do: __MODULE__

  defp ip_to_string({o0, o1, o2, o3, o4, o5, o6, o7}),
    do: "#{o0}.#{o1}.#{o2}.#{o3}.#{o4}.#{o5}.#{o6}.#{o7}"

  defp ip_to_string({o0, o1, o2, o3}), do: "#{o0}.#{o1}.#{o2}.#{o3}"
end
