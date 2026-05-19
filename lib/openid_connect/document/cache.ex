defmodule OpenIDConnect.Document.Cache do
  use GenServer
  alias OpenIDConnect.Document

  @max_size Application.compile_env(:openid_connect, :document_cache_max_size, 1_000)

  @doc "Starts the cache GenServer. Defaults to a registered name of `#{inspect(__MODULE__)}`."
  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  def init(_opts) do
    Process.send_after(self(), :gc, :timer.minutes(1))
    {:ok, %{}}
  end

  @doc "Inserts `document` under `uri`, scheduling its removal at the document's expiry."
  def put(pid \\ __MODULE__, uri, document) do
    GenServer.cast(pid, {:put, uri, document})
  end

  @doc "Returns the cached document for `uri`, bumping recency. Evicts expired entries on lookup."
  def fetch(pid \\ __MODULE__, uri) do
    GenServer.call(pid, {:fetch, uri})
  end

  @doc "Non-mutating lookup: returns the cached doc as-is, without bumping recency or evicting on expiry."
  def peek(pid \\ __MODULE__, uri) do
    GenServer.call(pid, {:peek, uri})
  end

  @doc "Returns the full cache state map. Primarily intended for introspection in tests."
  def flush(pid \\ __MODULE__) do
    GenServer.call(pid, :flush)
  end

  @doc "Empties the cache and cancels every scheduled removal timer."
  def clear(pid \\ __MODULE__) do
    GenServer.call(pid, :clear)
  end

  def handle_cast({:put, uri, document}, state) do
    if document_expired?(document) do
      {:noreply, state}
    else
      # Evict first so a prior timer's stale `{:remove, uri}` can't wipe this fresh entry.
      state = evict(state, uri)
      expires_in_seconds = expires_in_seconds(document.expires_at)
      timer_ref = Process.send_after(self(), {:remove, uri}, :timer.seconds(expires_in_seconds))
      state = Map.put(state, uri, {timer_ref, DateTime.utc_now(), document})
      {:noreply, state}
    end
  end

  def handle_call(:flush, _from, state) do
    {:reply, state, state}
  end

  def handle_call(:clear, _from, state) do
    for {_uri, {timer_ref, _last_fetched_at, _document}} <- state do
      Process.cancel_timer(timer_ref)
    end

    {:reply, :ok, %{}}
  end

  def handle_call({:fetch, uri}, _from, state) do
    case Map.fetch(state, uri) do
      {:ok, {timer_ref, _last_fetched_at, document}} ->
        if document_expired?(document) do
          {:reply, :error, evict(state, uri)}
        else
          state = Map.put(state, uri, {timer_ref, DateTime.utc_now(), document})
          {:reply, {:ok, document}, state}
        end

      :error ->
        {:reply, :error, state}
    end
  end

  def handle_call({:peek, uri}, _from, state) do
    reply =
      case Map.fetch(state, uri) do
        {:ok, {_timer_ref, _last_fetched_at, document}} -> {:ok, document}
        :error -> :error
      end

    {:reply, reply, state}
  end

  def handle_info({:remove, uri}, state) do
    {:noreply, Map.delete(state, uri)}
  end

  def handle_info(:gc, state) do
    state =
      if Enum.count(state) > @max_size do
        state
        |> Enum.sort_by(
          fn {_key, {_ref, last_fetched_at, _document}} -> last_fetched_at end,
          {:desc, DateTime}
        )
        |> Enum.take(@max_size)
        |> Enum.into(%{})
      else
        state
      end

    Process.send_after(self(), :gc, :timer.minutes(1))

    {:noreply, state}
  end

  # Drops `uri` from state, cancels its timer, and drains any queued `{:remove, ^uri}`.
  defp evict(state, uri) do
    case Map.pop(state, uri) do
      {nil, state} ->
        state

      {{timer_ref, _last_fetched_at, _document}, state} ->
        Process.cancel_timer(timer_ref)
        flush_remove_messages(uri)
        state
    end
  end

  defp flush_remove_messages(uri) do
    receive do
      {:remove, ^uri} -> flush_remove_messages(uri)
    after
      0 -> :ok
    end
  end

  defp expires_in_seconds(%DateTime{} = datetime) do
    max(DateTime.diff(datetime, DateTime.utc_now(), :second), 0)
  end

  defp document_expired?(%Document{expires_at: expires_at}) do
    DateTime.compare(expires_at, DateTime.utc_now()) != :gt
  end
end
