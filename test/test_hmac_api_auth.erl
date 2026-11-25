-module(test_hmac_api_auth).

-export([run/0]).

run() ->
    try
        test_valid_request(),
        test_tampering_is_detected(),
        test_replay_is_rejected(),
        test_timestamp_window(),
        test_rate_limiting(),
        test_unknown_client_and_bad_input(),
        test_secret_and_nonce_generation(),
        io:format("PASS: all HMAC API-authentication test groups completed.~n"),
        ok
    catch
        Class:Reason:Stack ->
            io:format("FAIL: ~p:~p~n~p~n", [Class, Reason, Stack]),
            halt(1)
    end.

test_valid_request() ->
    {Secret, Server0} = setup(),
    Now = 1000000,
    {ok, Request} = make_request(Secret, Now, <<"POST">>, <<"/api/jobs">>,
                                 <<"{\"job\":\"compile\"}">>),
    {ok, <<"{\"job\":\"compile\"}">>, _Server1} =
        hmac_api_auth:verify_request(Server0, Request, Now),
    pass("valid HMAC request is accepted and body is returned").

test_tampering_is_detected() ->
    {Secret, Server0} = setup(),
    OtherSecret = hmac_api_auth:generate_secret(),
    {ok, ServerWithTwoClients} = hmac_api_auth:register_client(
        Server0, <<"client-B">>, OtherSecret),
    Now = 2000000,
    {ok, Request} = make_request(Secret, Now, <<"POST">>, <<"/api/jobs">>,
                                 <<"original-body">>),
    TamperedBody = Request#{body := <<"changed-body">>},
    {error, invalid_mac, _} =
        hmac_api_auth:verify_request(Server0, TamperedBody, Now),
    TamperedPath = Request#{path := <<"/api/admin">>},
    {error, invalid_mac, _} =
        hmac_api_auth:verify_request(Server0, TamperedPath, Now),
    TamperedMethod = Request#{method := <<"DELETE">>},
    {error, invalid_mac, _} =
        hmac_api_auth:verify_request(Server0, TamperedMethod, Now),
    TamperedTimestamp = Request#{timestamp := Now + 1},
    {error, invalid_mac, _} =
        hmac_api_auth:verify_request(Server0, TamperedTimestamp, Now),
    TamperedNonce = Request#{nonce := crypto:strong_rand_bytes(16)},
    {error, invalid_mac, _} =
        hmac_api_auth:verify_request(Server0, TamperedNonce, Now),
    MovedToOtherClient = Request#{client_id := <<"client-B">>},
    {error, invalid_mac, _} =
        hmac_api_auth:verify_request(ServerWithTwoClients, MovedToOtherClient, Now),
    pass("body, path, method, timestamp, nonce, and client identity tampering are detected").

test_replay_is_rejected() ->
    {Secret, Server0} = setup(),
    Now = 3000000,
    {ok, Request} = make_request(Secret, Now, <<"GET">>, <<"/api/status">>, <<>>),
    {ok, <<>>, Server1} = hmac_api_auth:verify_request(Server0, Request, Now),
    {error, replayed_request, _Server2} =
        hmac_api_auth:verify_request(Server1, Request, Now + 1),
    pass("a previously accepted nonce cannot be replayed").

test_timestamp_window() ->
    {Secret, Server0} = setup(),
    Now = 4000000,
    {ok, StaleRequest} = make_request(Secret, Now - 5001, <<"GET">>,
                                      <<"/api/status">>, <<>>),
    {error, timestamp_out_of_range, _} =
        hmac_api_auth:verify_request(Server0, StaleRequest, Now),
    {ok, FutureRequest} = make_request(Secret, Now + 5001, <<"GET">>,
                                       <<"/api/status">>, <<>>),
    {error, timestamp_out_of_range, _} =
        hmac_api_auth:verify_request(Server0, FutureRequest, Now),
    pass("stale and future timestamps outside the allowed window are rejected").

test_rate_limiting() ->
    Secret = hmac_api_auth:generate_secret(),
    Server0 = hmac_api_auth:new_server(5000, 2, 10000),
    {ok, Server1} = hmac_api_auth:register_client(Server0, <<"client-A">>, Secret),
    Now = 5000000,
    {ok, GoodRequest} = make_request(Secret, Now, <<"POST">>, <<"/api/data">>,
                                    <<"payload">>),
    BadRequest = GoodRequest#{mac := <<0:256>>},
    {error, invalid_mac, Server2} =
        hmac_api_auth:verify_request(Server1, BadRequest, Now),
    {error, invalid_mac, Server3} =
        hmac_api_auth:verify_request(Server2, BadRequest, Now + 1),
    {error, rate_limited, Server4} =
        hmac_api_auth:verify_request(Server3, GoodRequest, Now + 2),
    {ok, FreshRequest} = make_request(Secret, Now + 10001, <<"POST">>,
                                     <<"/api/data">>, <<"payload">>),
    {ok, <<"payload">>, _Server5} =
        hmac_api_auth:verify_request(Server4, FreshRequest, Now + 10001),
    pass("invalid MAC attempts count toward a per-client rate limit").

test_unknown_client_and_bad_input() ->
    {Secret, Server0} = setup(),
    Now = 6000000,
    {ok, Request} = make_request(Secret, Now, <<"GET">>, <<"/api/status">>, <<>>),
    UnknownRequest = Request#{client_id := <<"unknown-client">>},
    {error, unknown_client, _} =
        hmac_api_auth:verify_request(Server0, UnknownRequest, Now),
    {error, invalid_request, _} =
        hmac_api_auth:verify_request(Server0, #{client_id => <<"client-A">>}, Now),
    {error, invalid_request_fields} = hmac_api_auth:create_request(
        Secret, <<"client-A">>, <<"POST">>, <<"/api/data">>, -1, <<>>),
    pass("unknown clients and malformed requests are rejected").

test_secret_and_nonce_generation() ->
    Secret1 = hmac_api_auth:generate_secret(),
    Secret2 = hmac_api_auth:generate_secret(),
    true = byte_size(Secret1) =:= 32,
    true = byte_size(Secret2) =:= 32,
    true = Secret1 =/= Secret2,
    {ok, Request1} = make_request(Secret1, 7000000, <<"GET">>, <<"/one">>, <<>>),
    {ok, Request2} = make_request(Secret1, 7000000, <<"GET">>, <<"/two">>, <<>>),
    Nonce1 = maps:get(nonce, Request1),
    Nonce2 = maps:get(nonce, Request2),
    true = byte_size(Nonce1) =:= 16,
    true = byte_size(Nonce2) =:= 16,
    true = Nonce1 =/= Nonce2,
    pass("secrets and per-request nonces use secure random byte generation").

setup() ->
    Secret = hmac_api_auth:generate_secret(),
    Server0 = hmac_api_auth:new_server(5000, 100, 10000),
    {ok, Server1} = hmac_api_auth:register_client(Server0, <<"client-A">>, Secret),
    {Secret, Server1}.

make_request(Secret, Timestamp, Method, Path, Body) ->
    hmac_api_auth:create_request(
        Secret, <<"client-A">>, Method, Path, Timestamp, Body).

pass(Message) ->
    io:format("PASS: ~s.~n", [Message]).
