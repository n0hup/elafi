use Mix.Config

config :logger, level: :debug

config :dnscache,
  udp_port_listen: 5355,
  udp_ip_listen: {127, 0, 0, 1},
  upstream_dns_server_ip: {192, 168, 1, 105},
  upstream_dns_server_port: 5335
