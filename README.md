# COP5615 – Weekly Assignment 13

## HMAC-Based API Request Authentication

### Objective

Implement a small Erlang simulator for authenticated API requests using HMAC-SHA256. A client and server share a secret. The client authenticates each request by attaching an HMAC calculated over the request's identity and content. The server independently calculates the expected HMAC and accepts the request only when the values match.

The implementation follows the November 18 lecture's discussion of HMAC for API calls, message integrity, provenance, timestamps, and replay protection.

### Requirements

1. Generate 256-bit client secrets and 128-bit request nonces with Erlang's secure random byte generator.
2. Calculate HMAC-SHA256 using Erlang's `crypto` library.
3. Authenticate the client ID, HTTP method, path, timestamp, nonce, and body together.
4. Use an unambiguous length-prefixed encoding for variable-length request fields.
5. Compare HMAC values using Erlang's constant-time `crypto:hash_equals/2` function.
6. Reject requests with invalid MACs, timestamps outside the configured window, unknown clients, or reused nonces.
7. Apply a per-client fixed-window rate limit. Invalid MAC attempts count toward the limit.

### Project Structure

```text
COP5615-Assignment-13/
├── src/
│   └── hmac_api_auth.erl
├── test/
│   └── test_hmac_api_auth.erl
├── Makefile
├── README.md
├── RUN.md
├── REPORT.md
└── .gitignore
```

### Implementation Scope

This is a local protocol simulator, not a running HTTP server. It models the client request-signing operation and the server verification/state-management operation. The server state is represented by Erlang maps and is passed explicitly between calls, making nonce consumption and rate-limit updates visible in the tests.

HMAC is a shared-secret mechanism. It provides message integrity and proves that the sender knows the shared secret, but it does not provide public verifiability or non-repudiation. The secret must be established and protected separately. In a real deployment, API traffic should also be protected by TLS.

### Run

```bash
make clean
make test
```

See `RUN.md` for the interactive shell demonstration.
