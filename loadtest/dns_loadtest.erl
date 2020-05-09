-module(dns_loadtest).

-author('istvan@lambdainisght.com').

-export([
  start/0,
  start/2,
  random_server/0,
  create_dns_request/0,
  send_request/4

]).

-define(SERVERS, [
  {server0, {127,0,0,1}, 5355},
  {server1, {127,0,0,1}, 5355}
]).

start() ->
  {_Name, Ip, Port} = random_server(),
  start(Ip, Port).

start(Ip, Port) ->
  {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
  {ok, Req} = create_dns_request(),
  {ok, Resp} = send_request(Socket, Ip, Port, Req),
  {header_id_int, HeaderIdInt} = parse_dns_reponse(Resp),
  {ok, HeaderIdInt}.

random_server() ->
  lists:nth(rand:uniform(length(?SERVERS)), ?SERVERS).

send_request(Socket, Ip, Port, Req) ->
	 gen_udp:send(Socket, Ip, Port, Req),
   {ok, {_Address, _Port, Resp}} = gen_udp:recv(Socket, 0, 500),
	 {ok, Resp}.

create_dns_request() ->
	ReqId = rand:uniform(65536),
  Header = <<ReqId:16, 0:1, 0:4, 0:1, 0:1,1:1, 0:1, 0:3, 0:4, 1:16, 0:16, 0:16, 0:16>>,
  Question = <<3, 119, 119, 119, 5, 105, 110, 100, 101, 120, 2, 104, 117, 0, 0, 1, 0, 1>>,
  {ok, <<Header/binary, Question/binary>>}.

parse_dns_reponse(<<HeaderIdInt:16/unsigned-integer, _Rest/binary>>) ->
  {header_id_int, HeaderIdInt}.

% , qr_int::unsigned-integer-size(1),
%            opcode_int::unsigned-integer-size(4), aa_int::unsigned-integer-size(1),
%            tc_int::unsigned-integer-size(1), rd_int::unsigned-integer-size(1),
%            ra_int::unsigned-integer-size(1), res1_int::unsigned-integer-size(1),
%            res2_int::unsigned-integer-size(1), res3_int::unsigned-integer-size(1),
%            rcode_int::unsigned-integer-size(4), header_qdcount_int::unsigned-integer-size(16),
%            header_ancount_int::unsigned-integer-size(16),
%            header_nscount_int::unsigned-integer-size(16),
%            header_arcount_int::unsigned-integer-size(16), rest::bits>>
%        ) do
%     {:header_id_int, header_id_int, :qr_int, qr_int, :opcode_int, opcode_int, :aa_int, aa_int,
%      :tc_int, tc_int, :rd_int, rd_int, :ra_int, ra_int, :res1_int, res1_int, :res2_int, res2_int,
%      :res3_int, res3_int, :rcode_int, rcode_int, :header_qdcount_int, header_qdcount_int,
%      :header_ancount_int, header_ancount_int, :header_nscount_int, header_nscount_int,
%      :header_arcount_int, header_arcount_int, :rest, rest}
%   end) ->

%   {ok,ok}.


  
  
