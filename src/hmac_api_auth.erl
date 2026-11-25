-module(hmac_api_auth).

-export([
    generate_secret/0,
    new_server/3,
    register_client/3,
    create_request/6,
    verify_request/3
]).

-define(SECRET_BYTES, 32).
-define(NONCE_BYTES, 16).
-define(MAC_BYTES, 32).
-define(MAX_BODY_BYTES, 1048576).
-define(MAX_TIMESTAMP, 18446744073709551615).

%% Generate a 256-bit client/server shared secret with the OS-backed CSPRNG.
generate_secret() ->
    crypto:strong_rand_bytes(?SECRET_BYTES).

%% MaxAgeMs is the allowed timestamp skew, MaxRequests is the number of
%% requests accepted per client in each WindowMs fixed-rate-limit window.
new_server(MaxAgeMs, MaxRequests, WindowMs)
  when is_integer(MaxAgeMs), MaxAgeMs > 0,
       is_integer(MaxRequests), MaxRequests > 0,
       is_integer(WindowMs), WindowMs > 0 ->
    #{
        clients => #{},
        used_nonces => #{},
        attempts => #{},
        max_age_ms => MaxAgeMs,
        max_requests => MaxRequests,
        window_ms => WindowMs
    };
new_server(_MaxAgeMs, _MaxRequests, _WindowMs) ->
    {error, invalid_configuration}.

register_client(Server, ClientId, Secret)
  when is_map(Server), is_binary(ClientId), byte_size(ClientId) > 0,
       byte_size(ClientId) =< 128, is_binary(Secret),
       byte_size(Secret) >= ?SECRET_BYTES ->
    Clients = maps:get(clients, Server),
    case maps:is_key(ClientId, Clients) of
        true -> {error, client_already_registered};
        false ->
            {ok, Server#{clients := maps:put(ClientId, Secret, Clients)}}
    end;
register_client(_Server, _ClientId, _Secret) ->
    {error, invalid_client}.

%% Create a signed API request. The nonce is generated for each request and
%% is covered by the HMAC along with the method, path, timestamp, and body.
create_request(Secret, ClientId, Method, Path, Timestamp, Body)
  when is_binary(Secret), byte_size(Secret) >= ?SECRET_BYTES,
       is_binary(ClientId), byte_size(ClientId) > 0,
       byte_size(ClientId) =< 128,
       is_binary(Method), byte_size(Method) > 0, byte_size(Method) =< 16,
       is_binary(Path), byte_size(Path) > 0, byte_size(Path) =< 2048,
       is_integer(Timestamp), Timestamp >= 0,
       Timestamp =< ?MAX_TIMESTAMP,
       is_binary(Body), byte_size(Body) =< ?MAX_BODY_BYTES ->
    Nonce = crypto:strong_rand_bytes(?NONCE_BYTES),
    RequestWithoutMac = #{
        client_id => ClientId,
        method => Method,
        path => Path,
        timestamp => Timestamp,
        nonce => Nonce,
        body => Body
    },
    Mac = request_mac(Secret, RequestWithoutMac),
    {ok, RequestWithoutMac#{mac => Mac}};
create_request(_Secret, _ClientId, _Method, _Path, _Timestamp, _Body) ->
    {error, invalid_request_fields}.

%% Return {ok, Body, NewServer} on success. Every validly-shaped request
%% from a registered client counts toward that client's rate limit,
%% including requests with an invalid HMAC.
verify_request(Server, Request, NowMs)
  when is_map(Server), is_map(Request), is_integer(NowMs), NowMs >= 0 ->
    case valid_request_shape(Request) of
        false -> {error, invalid_request, Server};
        true ->
            ClientId = maps:get(client_id, Request),
            Clients = maps:get(clients, Server),
            case maps:find(ClientId, Clients) of
                error -> {error, unknown_client, Server};
                {ok, Secret} ->
                    {Allowed, Server1} = record_attempt(Server, ClientId, NowMs),
                    case Allowed of
                        false -> {error, rate_limited, Server1};
                        true -> verify_authenticated_request(
                            Server1, Request, Secret, NowMs)
                    end
            end
    end;
verify_request(Server, _Request, _NowMs) when is_map(Server) ->
    {error, invalid_request, Server}.

verify_authenticated_request(Server, Request, Secret, NowMs) ->
    Timestamp = maps:get(timestamp, Request),
    MaxAgeMs = maps:get(max_age_ms, Server),
    case abs(NowMs - Timestamp) =< MaxAgeMs of
        false -> {error, timestamp_out_of_range, Server};
        true ->
            ExpectedMac = request_mac(Secret, Request),
            SuppliedMac = maps:get(mac, Request),
            case crypto:hash_equals(ExpectedMac, SuppliedMac) of
                false -> {error, invalid_mac, Server};
                true -> check_and_consume_nonce(Server, Request, NowMs)
            end
    end.

check_and_consume_nonce(Server, Request, NowMs) ->
    ClientId = maps:get(client_id, Request),
    Nonce = maps:get(nonce, Request),
    Server1 = prune_expired_nonces(Server, NowMs),
    UsedNonces = maps:get(used_nonces, Server1),
    NonceKey = {ClientId, Nonce},
    case maps:is_key(NonceKey, UsedNonces) of
        true -> {error, replayed_request, Server1};
        false ->
            Server2 = Server1#{used_nonces :=
                maps:put(NonceKey, NowMs, UsedNonces)},
            {ok, maps:get(body, Request), Server2}
    end.

record_attempt(Server, ClientId, NowMs) ->
    Attempts = maps:get(attempts, Server),
    MaxRequests = maps:get(max_requests, Server),
    WindowMs = maps:get(window_ms, Server),
    case maps:find(ClientId, Attempts) of
        error ->
            {true, Server#{attempts :=
                maps:put(ClientId, {NowMs, 1}, Attempts)}};
        {ok, {WindowStart, _Count}} when NowMs >= WindowStart + WindowMs ->
            {true, Server#{attempts :=
                maps:put(ClientId, {NowMs, 1}, Attempts)}};
        {ok, {WindowStart, Count}} when Count < MaxRequests ->
            {true, Server#{attempts :=
                maps:put(ClientId, {WindowStart, Count + 1}, Attempts)}};
        {ok, {_WindowStart, _Count}} ->
            {false, Server}
    end.

prune_expired_nonces(Server, NowMs) ->
    MaxAgeMs = maps:get(max_age_ms, Server),
    UsedNonces = maps:get(used_nonces, Server),
    KeptNonces = maps:filter(
        fun(_NonceKey, SeenAt) -> SeenAt + MaxAgeMs >= NowMs end,
        UsedNonces
    ),
    Server#{used_nonces := KeptNonces}.

request_mac(Secret, Request) ->
    Canonical = canonical_request(Request),
    crypto:mac(hmac, sha256, Secret, Canonical).

%% Length-prefix every variable field to avoid ambiguous concatenations.
%% The fixed-width timestamp is encoded as an unsigned 64-bit integer.
canonical_request(Request) ->
    ClientId = maps:get(client_id, Request),
    Method = maps:get(method, Request),
    Path = maps:get(path, Request),
    Timestamp = maps:get(timestamp, Request),
    Nonce = maps:get(nonce, Request),
    Body = maps:get(body, Request),
    <<
        (encode_field(ClientId))/binary,
        (encode_field(Method))/binary,
        (encode_field(Path))/binary,
        Timestamp:64/unsigned-big,
        (encode_field(Nonce))/binary,
        (encode_field(Body))/binary
    >>.

encode_field(Value) ->
    Size = byte_size(Value),
    <<Size:32/unsigned-big, Value/binary>>.

valid_request_shape(Request) ->
    map_size(Request) =:= 7 andalso
    is_binary(maps:get(client_id, Request, undefined)) andalso
    byte_size(maps:get(client_id, Request, <<>>)) > 0 andalso
    byte_size(maps:get(client_id, Request, <<>>)) =< 128 andalso
    is_binary(maps:get(method, Request, undefined)) andalso
    byte_size(maps:get(method, Request, <<>>)) > 0 andalso
    byte_size(maps:get(method, Request, <<>>)) =< 16 andalso
    is_binary(maps:get(path, Request, undefined)) andalso
    byte_size(maps:get(path, Request, <<>>)) > 0 andalso
    byte_size(maps:get(path, Request, <<>>)) =< 2048 andalso
    is_integer(maps:get(timestamp, Request, invalid)) andalso
    maps:get(timestamp, Request, -1) >= 0 andalso
    maps:get(timestamp, Request, ?MAX_TIMESTAMP + 1) =< ?MAX_TIMESTAMP andalso
    is_binary(maps:get(nonce, Request, undefined)) andalso
    byte_size(maps:get(nonce, Request, <<>>)) =:= ?NONCE_BYTES andalso
    is_binary(maps:get(body, Request, undefined)) andalso
    byte_size(maps:get(body, Request, <<>>)) =< ?MAX_BODY_BYTES andalso
    is_binary(maps:get(mac, Request, undefined)) andalso
    byte_size(maps:get(mac, Request, <<>>)) =:= ?MAC_BYTES.
