defmodule Dataz.Server do
  use GenServer
  require Logger
  alias :mnesia, as: Mnesia

  @spec start_link(any) :: :ignore | {:error, any} | {:ok, pid}
  def start_link(args) do
    Logger.info("Dataz.Server is starting")
    Logger.info("Dataz.Server.start_link, args: #{inspect(args)}")

    GenServer.start_link(
      __MODULE__,
      [],
      name: Dataz.Server
    )
  end

  def init() do
    Logger.info("Dataz.Server.init, args: #{inspect([])}")

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

    {:ok, %{}}
  end

  def handle_info(
        {},
        state
      ) do
  end
end
