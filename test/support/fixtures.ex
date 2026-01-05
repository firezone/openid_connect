defmodule OpenIDConnect.Fixtures do
  @moduledoc """
  Test fixtures for OpenIDConnect using Req.Test.
  """

  def start_fixture(provider, overrides \\ %{}) do
    test_name = unique_test_name()
    endpoint = "http://#{test_name}/"
    {jwks, overrides} = Map.pop(overrides, "jwks")

    Req.Test.stub(test_name, fn conn ->
      case conn.request_path do
        "/.well-known/jwks.json" ->
          {status_code, body, headers} = load_fixture(provider, "jwks")
          body = if jwks, do: jwks, else: body
          send_response(conn, status_code, body, headers)

        "/.well-known/discovery-document.json" ->
          {status_code, body, headers} = load_fixture(provider, "discovery_document")
          body = Map.merge(body, %{"jwks_uri" => "#{endpoint}.well-known/jwks.json"})
          body = Map.merge(body, overrides)
          send_response(conn, status_code, body, headers)

        _ ->
          # Unknown path - return 404
          conn
          |> Plug.Conn.put_status(404)
          |> Req.Test.json(%{error: "not_found"})
      end
    end)

    {test_name, "#{endpoint}.well-known/discovery-document.json"}
  end

  @doc """
  Creates a fixture with custom route handlers.

  The `custom_routes` parameter is a map of {method, path} => handler_fn.
  Handler functions receive conn and should return conn.

  Custom routes automatically update the discovery document endpoints:
  - {"POST", "/token"} sets token_endpoint
  - {"GET", "/userinfo"} sets userinfo_endpoint
  """
  def start_fixture_with_routes(provider, overrides \\ %{}, custom_routes \\ %{}) do
    test_name = unique_test_name()
    endpoint = "http://#{test_name}/"
    {jwks, overrides} = Map.pop(overrides, "jwks")

    # Auto-configure endpoints based on custom routes
    token_endpoint =
      if Map.has_key?(custom_routes, {"POST", "/token"}), do: "#{endpoint}token", else: nil

    userinfo_endpoint =
      if Map.has_key?(custom_routes, {"GET", "/userinfo"}), do: "#{endpoint}userinfo", else: nil

    Req.Test.stub(test_name, fn conn ->
      route_key = {conn.method, conn.request_path}

      cond do
        handler = Map.get(custom_routes, route_key) ->
          handler.(conn)

        handler = Map.get(custom_routes, {"*", conn.request_path}) ->
          handler.(conn)

        conn.request_path == "/.well-known/jwks.json" ->
          {status_code, body, headers} = load_fixture(provider, "jwks")
          body = if jwks, do: jwks, else: body
          send_response(conn, status_code, body, headers)

        conn.request_path == "/.well-known/discovery-document.json" ->
          {status_code, body, headers} = load_fixture(provider, "discovery_document")
          body = Map.merge(body, %{"jwks_uri" => "#{endpoint}.well-known/jwks.json"})
          body = Map.merge(body, overrides)
          # Set custom endpoints
          body =
            if token_endpoint, do: Map.put(body, "token_endpoint", token_endpoint), else: body

          body =
            if userinfo_endpoint,
              do: Map.put(body, "userinfo_endpoint", userinfo_endpoint),
              else: body

          send_response(conn, status_code, body, headers)

        true ->
          # Unknown path - return 404
          conn
          |> Plug.Conn.put_status(404)
          |> Req.Test.json(%{error: "not_found"})
      end
    end)

    {test_name, "#{endpoint}.well-known/discovery-document.json"}
  end

  def load_fixture(provider, type) do
    {%{status_code: status_code, body: body, headers: headers}, _} =
      Code.eval_file("test/fixtures/http/#{provider}/#{type}.exs")

    {status_code, body, headers}
  end

  def send_response(conn, status_code, body, headers) do
    conn =
      headers
      |> Enum.reduce(conn, fn {key, value}, conn ->
        # Plug requires lowercase header keys
        Plug.Conn.put_resp_header(conn, String.downcase(key), value)
      end)

    conn
    |> Plug.Conn.put_status(status_code)
    |> Req.Test.json(body)
  end

  def req_test_options(test_name) do
    [plug: {Req.Test, test_name}]
  end

  def unique_test_name do
    :"test_#{System.unique_integer([:positive, :monotonic])}"
  end
end
