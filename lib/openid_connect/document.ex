defmodule OpenIDConnect.Document do
  @doc """
  This module caches OIDC documents and their JWKs for a limited timeframe, which is min(`@refresh_time`, `document.remaining_lifetime`).
  """
  alias OpenIDConnect.Document.Cache

  defstruct raw: nil,
            authorization_endpoint: nil,
            end_session_endpoint: nil,
            token_endpoint: nil,
            userinfo_endpoint: nil,
            claims_supported: nil,
            response_types_supported: nil,
            jwks: nil,
            expires_at: nil

  @refresh_time_seconds Application.compile_env(
                          :openid_connect,
                          :document_max_expiration_seconds,
                          60 * 60
                        )

  @document_max_byte_size Application.compile_env(
                            :openid_connect,
                            :document_max_byte_size,
                            1024 * 1024 * 1024
                          )

  def fetch_document(uri) do
    with :error <- Cache.fetch(uri),
         {:ok, document_json, document_expires_at} <- fetch_remote_resource(uri),
         {:ok, document} <- build_document(document_json),
         {:ok, jwks_json, jwks_expires_at} <- fetch_remote_resource(document_json["jwks_uri"]),
         {:ok, jwks} <- from_certs(jwks_json) do
      now = DateTime.utc_now()

      expires_at =
        [
          DateTime.add(now, @refresh_time_seconds, :second),
          document_expires_at,
          jwks_expires_at
        ]
        |> Enum.reject(&is_nil/1)
        |> Enum.min(DateTime)

      document = %{
        document
        | jwks: jwks,
          expires_at: expires_at
      }

      _ = Cache.put(uri, document)

      {:ok, document}
    end
  end

  defp fetch_remote_resource(uri) when is_nil(uri), do: {:error, :invalid_discovery_document_uri}

  defp fetch_remote_resource(uri) do
    with {:ok, %{headers: headers, body: response, status: status}}
         when status in 200..299 <- read_response(uri),
         {:ok, json} <- JSON.decode(response) do
      expires_at =
        if remaining_lifetime = remaining_lifetime(headers) do
          DateTime.add(DateTime.utc_now(), remaining_lifetime, :second)
        end

      {:ok, json, expires_at}
    else
      {:ok, %{body: body, status: status}} ->
        {:error, {status, body}}

      other ->
        other
    end
  end

  defp read_response(uri) do
    collector = body_collector(@document_max_byte_size)

    case Req.get(uri, into: collector, retry: retry_enabled?()) do
      {:ok, %{body: {:error, :body_too_large}}} ->
        {:error, :discovery_document_is_too_large}

      {:ok, %{body: {:ok, body}} = response} ->
        {:ok, %{response | body: IO.iodata_to_binary(body)}}

      {:ok, response} ->
        {:ok, response}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp body_collector(max_byte_size) do
    fn {:data, data}, {req, resp} ->
      current_body =
        case resp.body do
          nil -> {:ok, []}
          "" -> {:ok, []}
          {:ok, _} = ok -> ok
          {:error, _} = error -> error
        end

      case current_body do
        {:error, _} = error ->
          {:cont, {req, %{resp | body: error}}}

        {:ok, acc} ->
          new_size = IO.iodata_length(acc) + byte_size(data)

          if new_size > max_byte_size do
            {:halt, {req, %{resp | body: {:error, :body_too_large}}}}
          else
            {:cont, {req, %{resp | body: {:ok, [acc, data]}}}}
          end
      end
    end
  end

  defp remaining_lifetime(headers) do
    headers = normalize_headers(headers)
    max_age = get_max_age(headers)
    age = get_age(headers)

    cond do
      not is_nil(max_age) and max_age > 0 and not is_nil(age) -> max_age - age
      not is_nil(max_age) and max_age > 0 -> max_age
      true -> nil
    end
  end

  defp normalize_headers(headers) do
    for {k, v} <- headers, into: %{} do
      {String.downcase(k), normalize_header_value(v)}
    end
  end

  defp normalize_header_value(values) when is_list(values), do: Enum.join(values, ", ")
  defp normalize_header_value(value) when is_binary(value), do: value

  defp get_max_age(headers) when is_map(headers) do
    cache_control = Map.get(headers, "cache-control", "")

    case Regex.run(~r"(?<=max-age=)\d+", cache_control) do
      [max_age] -> String.to_integer(max_age)
      _ -> nil
    end
  end

  defp get_age(headers) when is_map(headers) do
    case Map.get(headers, "age") do
      nil -> nil
      age -> String.to_integer(age)
    end
  end

  defp build_document(document_json) do
    keys = Map.keys(document_json)
    required_keys = ["jwks_uri", "authorization_endpoint", "token_endpoint"]

    if Enum.all?(required_keys, &(&1 in keys)) do
      document = %__MODULE__{
        raw: document_json,
        authorization_endpoint: Map.fetch!(document_json, "authorization_endpoint"),
        end_session_endpoint: Map.get(document_json, "end_session_endpoint"),
        token_endpoint: Map.fetch!(document_json, "token_endpoint"),
        userinfo_endpoint: Map.get(document_json, "userinfo_endpoint"),
        response_types_supported:
          Map.get(document_json, "response_types_supported")
          |> Enum.map(fn response_type ->
            response_type
            |> String.split()
            |> Enum.sort()
            |> Enum.join(" ")
          end),
        claims_supported:
          Map.get(document_json, "claims_supported")
          |> sort_claims()
      }

      {:ok, document}
    else
      {:error, :invalid_document}
    end
  end

  defp sort_claims(nil), do: nil
  defp sort_claims(claims), do: Enum.sort(claims)

  defp from_certs(certs) do
    {:ok, JOSE.JWK.from(certs)}
  rescue
    _ -> {:error, :invalid_jwks_certificates}
  end

  defp retry_enabled? do
    Application.get_env(:openid_connect, :retry_enabled, true)
  end
end
