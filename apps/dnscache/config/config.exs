use Mix.Config

# Application.get_env(:dnscache, :key)
config :dnscache, udp_port_listen: 53

import_config "#{Mix.env()}.exs"
