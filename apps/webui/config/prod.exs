use Mix.Config
config :logger, level: :info

config :webui,
  tcp_port_listen: 8088,
  tcp_ip_listen: {192, 168, 1, 110}
