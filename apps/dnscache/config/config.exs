use Mix.Config

config :dnscache, dns_port: 5355

import_config "#{Mix.env()}.exs"
