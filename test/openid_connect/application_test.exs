defmodule OpenIDConnect.ApplicationTest do
  use ExUnit.Case, async: true
  import OpenIDConnect.Application

  test "returns expected children" do
    assert children() == [
             OpenIDConnect.Document.Cache
           ]
  end
end
