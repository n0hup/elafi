defmodule WebuiTest do
  use ExUnit.Case
  doctest Webui

  test "greets the world" do
    assert Webui.hello() == :world
  end
end
