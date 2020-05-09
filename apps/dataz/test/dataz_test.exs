defmodule DatazTest do
  use ExUnit.Case
  doctest Dataz

  test "greets the world" do
    assert Dataz.hello() == :world
  end
end
