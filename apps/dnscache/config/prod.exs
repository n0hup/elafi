use Mix.Config
config :logger, level: :info

config :dnscache,
  udp_port_listen: 53,
  udp_ip_listen: {192, 168, 1, 110},
  upstream_dns_server_ip: {192, 168, 1, 105},
  upstream_dns_server_port: 5335
