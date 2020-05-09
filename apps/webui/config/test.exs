use Mix.Config

config :logger, level: :debug

config :webui,
  tcp_port_listen: 8088,
  tcp_ip_listen: {192, 168, 1, 110}
