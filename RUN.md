# Run Instructions

## 1. Prerequisites

Open a terminal in the `COP5615-Assignment-13` directory and confirm Erlang/OTP is installed:

```bash
erl -version
```

The project uses the standard Erlang `crypto` application and does not require third-party dependencies.

## 2. Compile and Run Tests

```bash
make clean
make test
```

The test suite should report seven passing groups and finish with:

```text
PASS: all HMAC API-authentication test groups completed.
```

## 3. What the Tests Cover

- Successful HMAC-authenticated API requests.
- Detection of changes to the request body, path, or method.
- Rejection of a previously accepted request (replay attempt).
- Rejection of stale and future timestamps outside the allowed window.
- Per-client rate limiting, including failed MAC attempts.
- Rejection of unknown clients and malformed requests.
- Secure generation of shared secrets and per-request nonces.

## 4. Optional Interactive Erlang Shell Example

First compile the module and start the Erlang shell with `ebin` on its code path:

```bash
make compile
erl -pa ebin
```

Run the following commands one at a time in the Erlang shell:

```erlang
% Create a 256-bit shared secret for the client.
Secret = hmac_api_auth:generate_secret().

% Create a server: 60-second timestamp window, 100 requests per minute.
Server0 = hmac_api_auth:new_server(60000, 100, 60000).

% Register the client with the same secret.
{ok, Server1} = hmac_api_auth:register_client(Server0, <<"client-A">>, Secret).

% Use the current Unix timestamp in milliseconds.
Now = erlang:system_time(millisecond).

% Build a signed API request.
{ok, Request} = hmac_api_auth:create_request(
    Secret,
    <<"client-A">>,
    <<"POST">>,
    <<"/api/jobs">>,
    Now,
    <<"{\"job\":\"compile\"}">>
).

% Verify the request on the server.
{ok, Body, Server2} = hmac_api_auth:verify_request(Server1, Request, Now).

% Inspect the accepted body.
Body.
```

The final expression should return:

```erlang
<<"{\"job\":\"compile\"}">>
```

To demonstrate replay protection, submit the same request again using the updated server state:

```erlang
{error, replayed_request, _Server3} =
    hmac_api_auth:verify_request(Server2, Request, Now + 1).
```

The request is rejected because its nonce has already been accepted.

## 5. Exit the Erlang Shell

```erlang
q().
```

## 6. Notes

- Timestamps are Unix time in milliseconds.
- The allowed timestamp difference is configured when the server is created.
- Each client must share its secret with the server through a separate secure provisioning process.
- A nonce is generated for every request and can be accepted only once during its validity period.
- The rate limiter uses a fixed window and counts requests with invalid MACs.
- This assignment simulates request authentication; it does not open a network socket or implement HTTP or TLS.
