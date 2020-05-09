use Mix.Config

config :mnesia,
  dir: 'elafidb_#{Mix.env()}'

import_config "#{Mix.env()}.exs"
