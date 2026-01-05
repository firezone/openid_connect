defmodule OpenIDConnect.Application do
  use Application

  def start(_type, _args) do
    opts = [strategy: :one_for_one, name: __MODULE__.Supervisor]
    Supervisor.start_link(children(), opts)
  end

  def children do
    [
      OpenIDConnect.Document.Cache
    ]
  end
end
