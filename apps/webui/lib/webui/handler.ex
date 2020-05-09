defmodule Webui.Handler do
  require Logger
  @behaviour :elli_handler
  alias :elli_request, as: Request

  @type allowed_request_type :: GET | POST

  def handle(:GET, ["ping"], _req) do
    {200, [], "pong"}
  end

  def handle(:GET, ["echo"], _req) do
    # Request.get_header()
    {200, [], <<0::8>>}
  end

  def handle(_method, _path, _req) do
    {404, [], "Not found"}
  end

  #   handle(Req, _Args) ->
  #     %% Delegate to our handler function
  #     handle(Req#req.method, elli_request:path(Req), Req).

  # handle('GET',[<<"hello">>, <<"world">>], _Req) ->
  #     %% Reply with a normal response. `ok' can be used instead of `200'
  #     %% to signal success.
  #     {ok, [], <<"Hello World!">>};

  # handle(_, _, _Req) ->
  #     {404, [], <<"Not Found">>}.

  # %% @doc Handle request events, like request completed, exception
  # %% thrown, client timeout, etc. Must return `ok'.
  # handle_event(_Event, _Data, _Args) ->
  #     ok.
end
