use Mix.Config

config :dnscache, 
	udp_port_listen: 53,
	udp_ip_listen: {192,168,1,110}

config :mnesia, 
	dir: 'elafidb_#{Mix.env}'

import_config "#{Mix.env()}.exs"
